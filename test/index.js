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

  describe('#signTypedData', function () {
    it('returns the expected value', function (done) {
      const address = firstAcct
      const privateKey = Buffer.from(privKeyHex, 'hex')
      const typedData = {
        types: {
          EIP712Domain: []
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {}
      }

      keyring.deserialize({ mnemonic: sampleMnemonic, numberOfAccounts: 1 }).then(function () {
        return keyring.signTypedData(address, typedData)
      }).then(function (sig) {
        const restored = sigUtil.recoverTypedSignature({ data: typedData, sig: sig })
        assert.equal(restored, sigUtil.normalize(address), 'recovered address')
        done()
      }).catch(function (reason) {
        console.error('failed because', reason)
      })
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
