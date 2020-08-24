const assert = require('assert')
const extend = require('xtend')
const HdKeyring = require('../')
const sigUtil = require('eth-sig-util')
const braveCrypto = require('brave-crypto')

// Sample account:
const privKeyHex = 'b8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952'

const sampleMnemonic = 'today dream pistol mountain response need slab label harvest behave party slam license skate skirt ritual call regular one ivory neglect mass only lift'
const firstAcct = '0xa567130473cc65df4760386ac22dc57e472c5bd9'
const secondAcct = '0xe07067315726583991ec50731d2bcdda2a5d299c'

const assertTypedArraysEquality = (a, b) => {
  let equal = false
  if (a.byteLength === b.byteLength) {
    equal = a.every((val, i) => val === b[i])
  }
  if (!equal) {
    console.log(a, b)
  }
  assert(equal)
}

const testKey = braveCrypto.getSeed(32)

describe('hd-keyring', function() {

  let keyring
  beforeEach(function() {
    keyring = new HdKeyring({encryptionKey: braveCrypto.getSeed(32)})
  })

  describe('constructor', function(done) {
    it('constructs', function (done) {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 2,
        encryptionKey: testKey
      })
      const accounts = keyring.getAccounts()
      .then((accounts) => {
        assert.equal(accounts[0], firstAcct)
        assert.equal(accounts[1], secondAcct)
        done()
      })
    })
  })

  describe('Keyring.type', function() {
    it('is a class property that returns the type string.', function() {
      const type = HdKeyring.type
      assert.equal(typeof type, 'string')
    })
  })

  describe('#type', function() {
    it('returns the correct value', function() {
      const type = keyring.type
      const correct = HdKeyring.type
      assert.equal(type, correct)
    })
  })

  describe('#serialize empty wallets.', function() {
    it('serializes a new mnemonic', function() {
      keyring.serialize()
      .then((output) => {
        assert.equal(output.numberOfAccounts, 0)
        assert.equal(output.mnemonic, null)
      })
    })
  })

  describe('#deserialize a private key', function() {
    it('serializes what it deserializes', function(done) {
      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1
      })
      .then(() => {
        assert.equal(keyring.wallets.length, 1, 'restores two accounts')
        return keyring.addAccounts(1)
      }).then(() => {
        return keyring.getAccounts()
      }).then((accounts) => {
        assert.equal(accounts[0], firstAcct)
        assert.equal(accounts[1], secondAcct)
        assert.equal(accounts.length, 2)

        return keyring.serialize()
      }).then((serialized) => {
        assert.equal(serialized.mnemonic, sampleMnemonic)
        done()
      })
    })
  })

  describe('initFromMnemonic', function () {
    const phrase12 = 'invite deer vivid fun attract sunny leave endless mutual teach around apology'
    const phrase24 = 'resist dice daughter wrap diary gain combine museum charge blame lizard master logic coffee local announce connect blast insane spider work march upper swear'
    it('returns expected value for bip39', function () {
      const result = keyring._initFromMnemonic(phrase12)
      assertTypedArraysEquality(result, new Buffer([198,240,17,131,9,253,8,111,11,216,253,20,246,146,126,6,226,140,128,239,121,65,64,213,0,144,3,6,161,4,157,67,184,192,184,91,123,204,43,196,172,141,165,120,234,133,198,72,151,130,81,200,198,211,113,90,160,140,12,163,17,37,115,40]))
    })
    it('returns expected value for 24 words', async function () {
      const result = await keyring._initFromMnemonic(phrase24)
      assertTypedArraysEquality(result, new Buffer([
        183,
        103,
        172,
        223,
        127,
        3,
        212,
        189,
        139,
        124,
        141,
        38,
        130,
        230,
        11,
        68,
        88,
        56,
        90,
        96,
        208,
        74,
        47,
        34,
        237,
        211,
        232,
        223,
        217,
        15,
        187,
        198
      ]))
    })
  })

  describe('initFromSeed', function () {
    const sampleMnemonics = [
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art',
      'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote'
    ]
    it('serializes to expected value 1', function () {
      keyring._initFromSeed(new Uint8Array(32))
      assert.equal(keyring.mnemonic, sampleMnemonics[0])
    })
    it('serializes to expected value 2', function () {
      keyring._initFromSeed(new Uint8Array([
        255, 255, 255, 255,
        255, 255, 255, 255,
        255, 255, 255, 255,
        255, 255, 255, 255,
        255, 255, 255, 255,
        255, 255, 255, 255,
        255, 255, 255, 255,
        255, 255, 255, 255
      ]))
      assert.equal(keyring.mnemonic, sampleMnemonics[1])
    })
    it('throws if byte length is not 32', function () {
      assert.throws(() => {
        keyring._initFromSeed(new Uint8Array(16))
      })
      assert.throws(() => {
        keyring._initFromSeed(new Uint8Array(24))
      })
    })
  })

  describe('#addAccounts', function() {
    describe('with no arguments', function() {
      it('creates a single wallet', function(done) {
        keyring.addAccounts()
        .then(() => {
          assert.equal(keyring.wallets.length, 1)
          done()
        })
      })
    })

    describe('with a numeric argument', function() {
      it('creates that number of wallets', function(done) {
        keyring.addAccounts(3)
        .then(() => {
          assert.equal(keyring.wallets.length, 3)
          done()
        })
      })
    })
  })

  describe('#getAccounts', function() {
    it('calls getAddress on each wallet', function(done) {

      // Push a mock wallet
      const desiredOutput = 'foo'
      keyring.wallets.push({
        getAddress() {
          return {
            toString() {
              return desiredOutput
            }
          }
        }
      })

      const output = keyring.getAccounts()
      .then((output) => {
        assert.equal(output[0], '0x' + desiredOutput)
        assert.equal(output.length, 1)
        done()
      })
    })
  })

  describe('#signPersonalMessage', function () {
    it('returns the expected value', function (done) {
      const address = firstAcct
      const privateKey = new Buffer(privKeyHex, 'hex')
      const message = '0x68656c6c6f20776f726c64'

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      })
      .then(() => {
        return keyring.signPersonalMessage(address, message)
      })
      .then((sig) => {
        assert.notEqual(sig, message, 'something changed')

        const restored = sigUtil.recoverPersonalSignature({
          data: message,
          sig,
        })

        assert.equal(restored, sigUtil.normalize(address), 'recovered address')
        done()
      })
      .catch((reason) => {
        console.error('failed because', reason)
      })
    })
  })

  describe('#signTypedData', () => {
    const privKey = Buffer.from(privKeyHex, 'hex')

    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!'
      }
    ]
    const msgParams = { data: typedData }

    it('can recover a basic signature', async () => {
      await keyring.addAccounts(1)
      const addresses = await keyring.getAccounts()
      const address = addresses[0]
      const sig = await keyring.signTypedData(address, typedData)
      const signedParams = Object.create(msgParams)
      signedParams.sig = sig;
      const restored = sigUtil.recoverTypedSignatureLegacy(signedParams)
      assert.equal(restored, address, 'recovered address')
    })
  })

  describe('#signTypedData_v1', () => {
    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!'
      }
    ]
    const msgParams = { data: typedData }

    it('signs in a compliant and recoverable way', async () => {
      await keyring.addAccounts(1)
      const addresses = await keyring.getAccounts()
      const address = addresses[0]
      const sig = await keyring.signTypedData(address, typedData)
      const signedParams = Object.create(msgParams)
      signedParams.sig = sig;
      const restored = sigUtil.recoverTypedSignatureLegacy(signedParams)
      assert.equal(restored, address, 'recovered address')
    })
  })

  describe('#signTypedData_v3', () => {
    it('signs in a compliant and recoverable way', async () => {
      const typedData = {
        types: {
          EIP712Domain: []
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {}
      }

      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      })
      const addresses = await keyring.getAccounts()
      const address = addresses[0]
      const sig = await keyring.signTypedData(address, typedData, { version: 'V3' })
      const restored = sigUtil.recoverTypedSignature({ data: typedData, sig: sig })
      assert.equal(restored, address, 'recovered address')
    })
  })

  describe('#signTypedData_v3 signature verification', () => {
    it('signs in a recoverable way.', async () => {
      const typedData = {"data":{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}}

      await keyring.addAccounts(1)
      const addresses = await keyring.getAccounts()
      const address = addresses[0]
      const sig = await keyring.signTypedData(address, typedData.data, { version: 'V3' })
      const signedData = Object.create(typedData)
      signedData.sig = sig
      const restored = sigUtil.recoverTypedSignature(signedData)
      assert.equal(restored, address, 'recovered address')
    })
  })

  describe('custom hd paths', function () {

    it('can deserialize with an hdPath param and generate the same accounts.', function (done) {
      const hdPathString = `m/44'/60'/0'/0`

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
        hdPath: hdPathString,
      })
      .then(() => {
        return keyring.getAccounts()
      })
      .then((addresses) => {
        assert.equal(addresses[0], firstAcct)
        return keyring.serialize()
      })
      .then((serialized) => {
        assert.equal(serialized.hdPath, hdPathString)
        done()
      })
      .catch((reason) => {
        console.error('failed because', reason)
      })
    })

    it('can deserialize with an hdPath param and generate different accounts.', function (done) {
      const hdPathString = `m/44'/60'/0'/1`

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
        hdPath: hdPathString,
      })
      .then(() => {
        return keyring.getAccounts()
      })
      .then((addresses) => {
        assert.notEqual(addresses[0], firstAcct)
        return keyring.serialize()
      })
      .then((serialized) => {
        assert.equal(serialized.hdPath, hdPathString)
        done()
      })
      .catch((reason) => {
        console.log('failed because', reason)
      })
    })
  })

  describe('create and restore 1k accounts', function () {
    it('should restore same accounts with no problem', async function () {
      this.timeout(20000)
      for (let i = 0; i < 1e3; i++) {
        keyring = new HdKeyring({
          numberOfAccounts: 1,
          encryptionKey: testKey
        }, true)
        const wallets = await keyring.init()
        assert(wallets.length)
        const originalAccounts = await keyring.getAccounts()
        assert(originalAccounts.length)
        const serialized = await keyring.serialize()
        const mnemonic = serialized.mnemonic

        keyring = new HdKeyring({
          numberOfAccounts: 1,
          mnemonic,
          encryptionKey: testKey
        })
        const restoredAccounts = await keyring.getAccounts()
        const msg = `Should restore same account from mnemonic: "${mnemonic}"`
        assert.equal(restoredAccounts[0], originalAccounts[0], msg)
      }

      return true
    })
  })
})
