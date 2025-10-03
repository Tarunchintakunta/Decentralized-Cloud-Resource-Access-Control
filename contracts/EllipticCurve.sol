// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

import "./Curve.sol";

library EllipticCurve {
    struct Point {
        uint256 x;
        uint256 y;
    }

    function g() internal pure returns (Point memory) {
        return Point(
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        );
    }

    function p() internal pure returns (uint256) {
        return 2**256 - 2**32 - 977;
    }

    function n() internal pure returns (uint256) {
        return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    }

    function isOnCurve(Point memory pt) internal pure returns (bool) {
        return Curve.onCurve(Curve.secp256k1(), pt.x, pt.y);
    }

    function add(Point memory p, Point memory q) internal pure returns (Point memory) {
        (uint256 x, uint256 y) = Curve.add(Curve.secp256k1(), p.x, p.y, q.x, q.y);
        return Point(x, y);
    }

    function mul(Point memory p, uint256 scalar) internal pure returns (Point memory) {
        (uint256 x, uint256 y) = Curve.mul(Curve.secp256k1(), p.x, p.y, scalar);
        return Point(x, y);
    }

    function decompress(uint256 x) internal pure returns (Point memory) {
        uint256 y2 = (x * x * x + 7) % p();
        uint256 y = expMod(y2, (p() + 1) / 4, p());
        if (y * y % p() != y2) {
            y = p() - y;
        }
        return Point(x, y);
    }

    function expMod(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256) {
        uint256 res = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1) res = (res * base) % mod;
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return res;
    }
}
