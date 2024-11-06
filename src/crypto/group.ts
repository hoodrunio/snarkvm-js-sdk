import { ExtendedPoint } from '@noble/ed25519';
import { ICryptoGroup, RawGroup } from '../core/types';
import { Scalar } from './scalar';
import { CryptoError } from '../core/errors';

export class Group implements ICryptoGroup {
    private readonly point: ExtendedPoint;
    static readonly BASE_POINT: Group = new Group(ExtendedPoint.BASE);

    private constructor(point: ExtendedPoint) {
        if (!point) {
            throw new CryptoError('Invalid group point');
        }
        this.point = point;
    }

    static fromBytes(bytes: Uint8Array): Group {
        try {
            if (!(bytes instanceof Uint8Array)) {
                throw new CryptoError('Input must be Uint8Array');
            }
            if (bytes.length !== 32) {
                throw new CryptoError('Input must be 32 bytes');
            }
            
            const point = ExtendedPoint.fromHex(Buffer.from(bytes).toString('hex'));
            if (!point.isOnCurve()) {
                throw new CryptoError('Point is not on curve');
            }
            
            return new Group(point);
        } catch (error) {
            throw new CryptoError('Invalid group element encoding');
        }
    }

    add(other: Group): Group {
        try {
            const newPoint = this.point.add(other.point);
            return new Group(newPoint);
        } catch (error) {
            throw new CryptoError('Group addition failed');
        }
    }

    multiply(scalar: Scalar): Group {
        try {
            const scalarValue = scalar.toBigInt();
            const newPoint = this.point.multiply(scalarValue);
            return new Group(newPoint);
        } catch (error) {
            if (error instanceof CryptoError) {
                throw error;
            }
            throw new CryptoError('Group multiplication failed');
        }
    }

    subtract(other: Group): Group {
        try {
            const negativePoint = other.point.negate();
            const newPoint = this.point.add(negativePoint);
            return new Group(newPoint);
        } catch (error) {
            throw new CryptoError('Group subtraction failed');
        }
    }

    equals(other: Group): boolean {
        return this.point.equals(other.point);
    }

    toRawBytes(): RawGroup {
        return this.toBytes();
    }

    toBytes(): Uint8Array {
        return new Uint8Array(this.point.toRawBytes());
    }

    toString(): string {
        return Buffer.from(this.toBytes()).toString('hex');
    }

    isOnCurve(): boolean {
        try {
            // Ed25519 curve equation: -x^2 + y^2 = 1 - (121665/121666)x^2y^2
            const point = this.point;
            return point.isValid();
        } catch (error) {
            return false;
        }
    }

    isValid(): boolean {
        try {
            if (!this.point) return false;
            
            // Ed25519 curve equation check
            const { x, y, z, t } = this.point;
            const x2 = x.multiply(x);
            const y2 = y.multiply(y);
            const z2 = z.multiply(z);
            const t2 = t.multiply(t);
            
            // -x^2 + y^2 = 1 - (121665/121666)x^2y^2
            return x2.negate().add(y2).equals(
                BigInt(1).subtract(
                    BigInt(121665)
                    .multiply(x2)
                    .multiply(y2)
                    .divide(BigInt(121666))
                )
            );
        } catch {
            return false;
        }
    }
} 