export class Bech32m {
    private static readonly CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    private static readonly CHARSET_REV = new Map([...this.CHARSET].map((char, idx) => [char, idx]));
    private static readonly GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    private static readonly M = 0x2bc830a3;

    static encode(hrp: string, data: Uint8Array): string {
        const words = this.convertBits(Array.from(data), 8, 5, true);
        const checksummed = this.createChecksum(hrp, words);
        
        return `${hrp}1${[...words, ...checksummed]
            .map(v => this.CHARSET.charAt(v))
            .join('')}`;
    }

    static decode(str: string): { hrp: string, data: Uint8Array } {
        if (str.length < 8 || str.length > 90) {
            throw new Error('Invalid bech32 string length');
        }

        const lowered = str.toLowerCase();
        const uppered = str.toUpperCase();
        if (str !== lowered && str !== uppered) {
            throw new Error('Mixed-case string');
        }

        str = lowered;
        const split = str.lastIndexOf('1');
        if (split < 1 || split + 7 > str.length) {
            throw new Error('Invalid separator position');
        }

        const hrp = str.slice(0, split);
        const dataChars = str.slice(split + 1);
        if (!this.verifyChecksum(hrp, [...dataChars].map(c => this.CHARSET_REV.get(c)!))) {
            throw new Error('Invalid checksum');
        }

        const data = dataChars.slice(0, -6).split('').map(c => this.CHARSET_REV.get(c)!);
        return {
            hrp,
            data: new Uint8Array(this.convertBits(data, 5, 8, false))
        };
    }

    private static convertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] {
        let acc = 0;
        let bits = 0;
        const result: number[] = [];
        const maxv = (1 << toBits) - 1;

        for (const value of data) {
            if (value < 0 || value >> fromBits !== 0) {
                throw new Error('Invalid value');
            }
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                result.push((acc >> bits) & maxv);
            }
        }

        if (pad) {
            if (bits > 0) {
                result.push((acc << (toBits - bits)) & maxv);
            }
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
            throw new Error('Invalid padding');
        }

        return result;
    }

    private static createChecksum(hrp: string, data: number[]): number[] {
        const values = [...this.hrpExpand(hrp), ...data];
        const poly = this.polymod([...values, 0, 0, 0, 0, 0, 0]) ^ this.M;
        return [0, 1, 2, 3, 4, 5].map(i => (poly >> (5 * (5 - i))) & 31);
    }

    private static verifyChecksum(hrp: string, data: number[]): boolean {
        return this.polymod([...this.hrpExpand(hrp), ...data]) === this.M;
    }

    private static hrpExpand(hrp: string): number[] {
        const result: number[] = [];
        for (const c of hrp) {
            result.push(c.charCodeAt(0) >> 5);
        }
        result.push(0);
        for (const c of hrp) {
            result.push(c.charCodeAt(0) & 31);
        }
        return result;
    }

    private static polymod(values: number[]): number {
        let chk = 1;
        for (const value of values) {
            const top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ value;
            for (let i = 0; i < 5; ++i) {
                if ((top >> i) & 1) {
                    chk ^= this.GENERATOR[i];
                }
            }
        }
        return chk;
    }

    private static validateHrp(hrp: string): boolean {
        if (hrp.length < 1 || hrp.length > 83) {
            return false;
        }
        
        const VALID_CHARSET = /^[a-z][a-z0-9]*$/;
        if (!VALID_CHARSET.test(hrp)) {
            return false;
        }
        
        return true;
    }
}