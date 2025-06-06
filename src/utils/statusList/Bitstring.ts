export class Bitstring {
  private buffer: Uint8Array;

  constructor({ buffer, length }: { buffer?: Uint8Array; length?: number }) {
    if (buffer) {
      this.buffer = buffer;
    } else if (length) {
      this.buffer = new Uint8Array(Math.ceil(length / 8));
    } else {
      throw new Error('Either buffer or length must be provided');
    }
  }

  set(position: number, value: boolean): void {
    const byteIndex = Math.floor(position / 8);
    const bitIndex = position % 8;
    if (value) {
      this.buffer[byteIndex] |= (1 << bitIndex);
    } else {
      this.buffer[byteIndex] &= ~(1 << bitIndex);
    }
  }

  get(position: number): boolean {
    const byteIndex = Math.floor(position / 8);
    const bitIndex = position % 8;
    return (this.buffer[byteIndex] & (1 << bitIndex)) !== 0;
  }

  static async decodeBits({ encoded }: { encoded: string }): Promise<Uint8Array> {
    const decoded = Buffer.from(encoded, 'base64');
    return new Uint8Array(decoded);
  }

  async encodeBits(): Promise<string> {
    return Buffer.from(this.buffer).toString('base64');
  }
} 