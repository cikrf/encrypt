export type Point = [string, string] | string

export type Config = {
  q: string;
  hashLength: string;
  mainKey: Point;
  basePoint: Point;
  pedersenBase: Point;
  compressed?: boolean;
  packed?: boolean;
}

export type KeyPair = { privateKey: string, publicKey: Point }

export type RangeProof = [
  Point,
  Point,
  Point,
  Point,
  Point,
  Point,
  string,
  string,
  string,
  string,
]

export type EqualityOfDLExProof = [
  string,
  Point,
  Point
]

export type EncryptedBulletin = [RangeProof[], EqualityOfDLExProof]

