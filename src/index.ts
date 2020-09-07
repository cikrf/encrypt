import { Config, EncryptedBulletin, EqualityOfDLExProof, KeyPair, Point, RangeProof } from './interfaces'
import * as elliptic from 'elliptic'
import * as crypto from 'crypto-js'
import * as BN from 'bn.js'

type BasePoint = elliptic.curve.base.BasePoint

export class Encrypt {
  private readonly ec: elliptic.ec
  private readonly base: BasePoint
  private readonly pointAtInfinity: BasePoint
  private readonly mainKey: BasePoint
  private readonly pedersenBase: BasePoint

  constructor(
    private readonly cryptoParams: Config,
  ) {
    this.ec = new elliptic.ec('secp256k1')
    const { mainKey, basePoint, pedersenBase } = this.cryptoParams
    this.base = this.createPoint(basePoint)
    this.mainKey = this.createPoint(mainKey)
    this.pointAtInfinity = this.base.add(this.base.neg())
    this.pedersenBase = this.createPoint(pedersenBase)
  }

  private createPoint(point: Point): BasePoint {
    const x_hex = new BN(point[0]).toString(16).padStart(64, '0')
    const y_hex = new BN(point[1]).toString(16).padStart(64, '0')
    return this.ec.keyFromPublic(`04${x_hex}${y_hex}`, 'hex').getPublic()
  }

  private generatePrivateKey(): BN {
    return new BN(this.ec.genKeyPair().getPrivate().toString())
  }

  private generateRandomFromScalarField(): BN {
    return this.generatePrivateKey()
  }

  private generateRandomLessThan(n: BN): BN {
    let currentMaxNumber = new BN(2).pow(new BN(521))
    let randomNumber = this.generateRandomFromScalarField().umod(n)

    while (n > currentMaxNumber) {
      randomNumber.imul(this.generateRandomFromScalarField())
      currentMaxNumber.imul(currentMaxNumber)
    }

    return randomNumber.umod(n)
  }

  private hashPoints(points: BasePoint[]): BN {
    const sha256 = crypto.algo.SHA256.create()

    points.map((point: BasePoint) => {
      const [x, y] = this.asPoint(point)
      sha256.update(`${x},${y},`)
    })

    const hash = sha256.finalize()

    return new BN(hash.toString(crypto.enc.Hex), 16)
  }

  private asPoint(point: BasePoint): Point | any {
    if (point.isInfinity()) {
      throw new Error('Calculation error')
    }
    return [point.getX().toString(), point.getY().toString()]
  }

  private calculateRangeProof(vote: number, A: BasePoint, B: BasePoint, r: BN, publicKey: BasePoint): RangeProof {

    const { q, hashLength } = this.cryptoParams

    const n: BN = new BN(2).pow(new BN(hashLength))

    let points: Point[] = []
    let scalars: Array<string | BN> = []

    if (vote === 0) {
      const c1 = this.generateRandomLessThan(n)

      const r1_ss = this.generateRandomFromScalarField()

      const B_s = B.add(this.base.neg())
      const A1_s = this.base.mul(r1_ss).add(A.mul(c1).neg())
      const B1_s = publicKey.mul(r1_ss).add(B_s.mul(c1).neg())

      const r0_s = this.generateRandomFromScalarField()

      const A0_s = this.base.mul(r0_s)
      const B0_s = publicKey.mul(r0_s)

      const c = this.hashPoints([publicKey, A, B, A0_s, B0_s, A1_s, B1_s])
      const c0 = c.add(c1.neg()).umod(n)

      const r0_ss = r0_s.add(c0.mul(r)).umod(new BN(q))

      points = [A, B, A0_s, A1_s, B0_s, B1_s].map(this.asPoint.bind(this))
      scalars = [c0, c1, r0_ss, r1_ss]
    } else if (vote === 1) {
      const c0 = this.generateRandomLessThan(n)

      const r0_ss = this.generateRandomFromScalarField()

      const B_s = B
      const A0_s = this.base.mul(r0_ss).add(A.mul(c0).neg())
      const B0_s = publicKey.mul(r0_ss).add(B_s.mul(c0).neg())

      const r1_s = this.generateRandomFromScalarField()

      const A1_s = this.base.mul(r1_s)
      const B1_s = publicKey.mul(r1_s)

      const c = this.hashPoints([publicKey, A, B, A0_s, B0_s, A1_s, B1_s])

      const c1 = c.add(c0.neg()).umod(n)

      const r1_ss = r1_s.add(c1.mul(r)).umod(new BN(q))

      points = [A, B, A0_s, A1_s, B0_s, B1_s].map(this.asPoint.bind(this))
      scalars = [c0, c1, r0_ss, r1_ss]

    } else {
      points = Array(6).fill(this.pointAtInfinity)
      scalars = ['0', '0', '0', '0']
    }
    return [...points, ...scalars.map(String)] as RangeProof
  }

  private proveEqualityOfDLEx(
    x: BN,
    Y1: BasePoint,
    Y2: BasePoint,
    listOfRs: BasePoint[],
  ): EqualityOfDLExProof {
    const { q } = this.cryptoParams
    const G1 = this.base
    const G2 = this.mainKey
    const u = this.generateRandomFromScalarField()
    const U1 = G1.mul(u)
    const U2 = G2.mul(u)
    const v = this.hashPoints([U1, U2, G1, Y1, G2, Y2, ...listOfRs])
    const w = x.mul(v).add(u).umod(new BN(q))
    return [w.toString(), this.asPoint(U1), this.asPoint(U2)]
  }

  public makeEncryptedBulletin(bulletin: number[]): EncryptedBulletin {
    if (bulletin.reduce((a, b) => a + b, 0) !== 1) {
      throw new Error('Bad bulletin')
    }

    const { q } = this.cryptoParams
    let sumR = this.pointAtInfinity
    let sumC = this.pointAtInfinity
    let sumr = new BN(0)
    const listOfRs: BasePoint[] = []

    const encryptedBulletin = bulletin.map((vote) => {
      const message = this.base.mul(new BN(vote))
      const r = this.generateRandomFromScalarField()
      const R = this.base.mul(r)
      const C = this.mainKey.mul(r).add(message)

      sumR = sumR.add(R)
      sumC = sumC.add(C)
      sumr = sumr.add(r).umod(new BN(q))
      listOfRs.push(R)
      return this.calculateRangeProof(vote, R, C, r, this.mainKey)
    })

    const sumRangeProof = this.proveEqualityOfDLEx(
      sumr,
      sumR,
      sumC.add(this.base.neg()),
      listOfRs,
    )
    return [encryptedBulletin, sumRangeProof]
  }

  public calculateMainKey(keyPairs: KeyPair[]): Point {
    const mainKey = keyPairs.reduce((acc, keyPair) => {
      const point = this.createPoint(keyPair.publicKey)
      const unblindedPublicKey = point.add(this.pedersenBase.neg().mul(new BN(keyPair.privateKey)))
      return acc.add(unblindedPublicKey)
    }, this.pointAtInfinity)
    return [mainKey.getX().toString(), mainKey.getY().toString()]
  }

}
