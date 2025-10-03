declare module 'elliptic' {
    namespace ec {
        interface KeyPair {
            getPublic(): any;
            getPrivate(): any;
        }

        interface EC {
            curve: {
                n: any;
            };
            g: any;
            keyFromPrivate(priv: any): KeyPair;
            keyFromPublic(pub: any): KeyPair;
        }
    }

    class ec {
        constructor(curve: string);
        curve: {
            n: any;
        };
        g: any;
        keyFromPrivate(priv: any): ec.KeyPair;
        keyFromPublic(pub: any): ec.KeyPair;
    }

    export { ec };
}