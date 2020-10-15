import { PKCEHelper } from 'abstract-pkce';
export type { PKCEHelper, PKCEChallenge } from 'abstract-pkce';
export declare type PKCEHelperLegacyBrowser = PKCEHelper<string>;
export declare const createPKCEHelper: (isHMAC?: boolean) => PKCEHelperLegacyBrowser;
