// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

library Curve {
    uint256 constant internal A = 0;
    uint256 constant internal B = 7;
    uint256 constant internal P = 2**256 - 2**32 - 977;
    uint256 constant internal N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    struct EllipticCurve {
        uint256 a;
        uint256 b;
        uint256 p;
        uint256 n;
    }

    function secp256k1() internal pure returns (EllipticCurve memory) {
        return EllipticCurve(A, B, P, N);
    }

    function onCurve(EllipticCurve memory curve, uint256 x, uint256 y) internal pure returns (bool) {
        return (y * y) % curve.p == (x * x * x + curve.a * x + curve.b) % curve.p;
    }

    function add(EllipticCurve memory curve, uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal pure returns (uint256, uint256) {
        if (x1 == x2 && y1 == y2) {
            return double(curve, x1, y1);
        }
        return _add(curve, x1, y1, x2, y2);
    }

    function double(EllipticCurve memory curve, uint256 x, uint256 y) internal pure returns (uint256, uint256) {
        uint256 s = (3 * x * x + curve.a) * inverseMod(2 * y, curve.p);
        uint256 x3 = (s * s - 2 * x);
        uint256 y3 = (s * (x - x3) - y);
        return (x3 % curve.p, y3 % curve.p);
    }

    function _add(EllipticCurve memory curve, uint256 x1, uint256 y1, uint256 x2, uint256 y2) private pure returns (uint256, uint256) {
        uint256 s = (y2 - y1) * inverseMod(x2 - x1, curve.p);
        uint256 x3 = (s * s - x1 - x2);
        uint256 y3 = (s * (x1 - x3) - y1);
        return (x3 % curve.p, y3 % curve.p);
    }

    function mul(EllipticCurve memory curve, uint256 x, uint256 y, uint256 scalar) internal pure returns (uint256, uint256) {
        uint256 currentX = x;
        uint256 currentY = y;
        for (uint256 i = 0; i < 255; i++) {
            (currentX, currentY) = double(curve, currentX, currentY);
            if ((scalar >> (255 - i - 1)) & 1 == 1) {
                (currentX, currentY) = add(curve, currentX, currentY, x, y);
            }
        }
        return (currentX, currentY);
    }

    function inverseMod(uint256 k, uint256 p) private pure returns (uint256) {
        if (k == 0) revert("Curve: division by zero");
        if (k > p) k %= p;
        return k**(p - 2);
    }
}
