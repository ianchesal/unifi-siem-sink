import dgram from 'node:dgram';
import { parseMessage } from '../parser/index.js';
import { type Db, insertEvent } from '../storage/db.js';

export interface SyslogListener {
  droppedCount(): number;
  close(): Promise<void>;
}

export interface SyslogListenerOptions {
  port: number;
  bindAddress: string;
  maxMessageBytes: number;
}

export function startSyslogListener(
  db: Db,
  options: SyslogListenerOptions
): Promise<SyslogListener> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let dropped = 0;

    socket.on('message', (msg) => {
      if (msg.byteLength > options.maxMessageBytes) {
        dropped += 1;
        return;
      }
      try {
        const raw = msg.toString('utf8');
        const event = parseMessage(raw);
        insertEvent(db, event);
      } catch {
        // Never let a parse/insert failure (e.g. transient SQLite lock
        // contention) escape the socket's 'message' handler and crash
        // the process. This service must keep listening.
      }
    });

    socket.once('error', reject);

    socket.bind(options.port, options.bindAddress, () => {
      socket.removeListener('error', reject);
      // Register a permanent, non-throwing error handler so a runtime
      // socket error (e.g. ECONNRESET from an ICMP port-unreachable)
      // never becomes an unhandled EventEmitter error and crashes the
      // process.
      socket.on('error', () => {
        // Swallow. The socket may still be usable; if it isn't, callers
        // will notice no more events arrive. We deliberately don't
        // rethrow here.
      });
      resolve({
        droppedCount: () => dropped,
        close: () => new Promise<void>((res) => socket.close(() => res())),
      });
    });
  });
}
