import { describe, it, expect, vi } from 'vitest';
import { createLogger } from '../src/logger.js';

describe('createLogger', () => {
  it('logs at or below the configured threshold', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createLogger('info');
    logger.info('hello');
    logger.debug('should not print');
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });

  it('error level suppresses info and debug', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const logger = createLogger('error');
    logger.info('suppressed');
    logger.error('shown');
    expect(logSpy).not.toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalledTimes(1);
    logSpy.mockRestore();
    errorSpy.mockRestore();
  });
});
