import dgram from 'node:dgram';
import { parseMessage } from '../parser/index.js';
import { insertEvent, type Db } from '../storage/db.js';

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
      const raw = msg.toString('utf8');
      const event = parseMessage(raw);
      insertEvent(db, event);
    });

    socket.once('error', reject);

    socket.bind(options.port, options.bindAddress, () => {
      socket.removeListener('error', reject);
      resolve({
        droppedCount: () => dropped,
        close: () => new Promise<void>((res) => socket.close(() => res())),
      });
    });
  });
}
