/* global chrome */
const EventEmitter = require('events').EventEmitter
const hdkey = require('ethereumjs-wallet/hdkey')
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')
const braveCrypto = require('brave-crypto')

// Options:
const hdPathString = `m/44'/60'/0'/0`
const type = 'HD Key Tree'

// Utility methods to convert between uint8array and arraybuffer
const uint8ToArrayBuf = (array) => {
  return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
}
const bufToUint8Array = (buf) => {
  return new Uint8Array(buf)
}

// polyfill chrome.braveWallets API for tests
if (typeof global === 'object' && global.it) {
  if (typeof chrome === 'undefined') {
    var chrome = {}
  }
  if (!chrome.braveWallet) {
    chrome.braveWallet = {}
    chrome.braveWallet.getWalletSeed = (key, cb) => {
      // Just use 32 random bytes generated in JS for now
      const seed = braveCrypto.getSeed(32)
      // The chrome.* API takes and returns arraybuffers
      cb(uint8ToArrayBuf(seed))
    }
  }
}

class HdKeyring extends EventEmitter {

  /* PUBLIC METHODS */

  constructor (opts = {}, skipInit = false) {
    super()
    this.type = type
    this.deserialize(opts, skipInit)
  }

  serialize () {
    return Promise.resolve({
      mnemonic: this.mnemonic,
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath
    })
  }

  deserialize (opts = {}, skipInit = false) {
    this.opts = opts || {}
    this.wallets = []
    this.mnemonic = null
    this.root = null
    this.hdPath = opts.hdPath || hdPathString
    this.encryptionKey = opts.encryptionKey
    if (skipInit !== true) {
      // Useful for tests since init is async and must be called separately if
      // we want an assertion to run after init is finished
      return this.init()
    }
  }

  init () {
    if (this.opts.mnemonic) {
      this._initFromMnemonic(this.opts.mnemonic)
    }
    if (this.opts.numberOfAccounts) {
      return this.addAccounts(this.opts.numberOfAccounts)
    }
    return Promise.resolve([])
  }

  async addAccounts (numberOfAccounts = 1) {
    if (!this.root) {
      if (!this.encryptionKey) {
        throw new Error('Cannot initialize wallet without an encryption key')
      }
      // chrome.braveWallet.getWalletSeed permission must ONLY be granted to
      // this extension
      if (typeof chrome === 'object' && chrome.braveWallet) {
        const promiseGetSeed = (key) =>
          new Promise((resolve) => chrome.braveWallet.getWalletSeed(key, resolve))
        const seed = await promiseGetSeed(uint8ToArrayBuf(this.encryptionKey))
        this._initFromSeed(bufToUint8Array(seed))
      } else {
        throw new Error('chrome.braveWallet is not defined')
      }
    }

    const oldLen = this.wallets.length
    const newWallets = []
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = this.root.deriveChild(i)
      const wallet = child.getWallet()
      newWallets.push(wallet)
      this.wallets.push(wallet)
    }
    const hexWallets = newWallets.map((w) => {
      return sigUtil.normalize(w.getAddress().toString('hex'))
    })
    return Promise.resolve(hexWallets)
  }

  getAccounts () {
    return Promise.resolve(this.wallets.map((w) => {
      return sigUtil.normalize(w.getAddress().toString('hex'))
    }))
  }

  // tx is an instance of the ethereumjs-transaction class.
  signTransaction (address, tx) {
    const wallet = this._getWalletForAccount(address)
    var privKey = wallet.getPrivateKey()
    tx.sign(privKey)
    return Promise.resolve(tx)
  }

  // For eth_sign, we need to sign transactions:
  // hd
  signMessage (withAccount, data) {
    const wallet = this._getWalletForAccount(withAccount)
    const message = ethUtil.stripHexPrefix(data)
    var privKey = wallet.getPrivateKey()
    var msgSig = ethUtil.ecsign(new Buffer(message, 'hex'), privKey)
    var rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage (withAccount, msgHex) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = ethUtil.stripHexPrefix(wallet.getPrivateKey())
    const privKeyBuffer = new Buffer(privKey, 'hex')
    const sig = sigUtil.personalSign(privKeyBuffer, { data: msgHex })
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData (withAccount, typedData) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = ethUtil.toBuffer(wallet.getPrivateKey())
    const signature = sigUtil.signTypedData(privKey, { data: typedData })
    return Promise.resolve(signature)
  }

  // For eth_sign, we need to sign transactions:
  newGethSignMessage (withAccount, msgHex) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = wallet.getPrivateKey()
    const msgBuffer = ethUtil.toBuffer(msgHex)
    const msgHash = ethUtil.hashPersonalMessage(msgBuffer)
    const msgSig = ethUtil.ecsign(msgHash, privKey)
    const rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  exportAccount (address) {
    const wallet = this._getWalletForAccount(address)
    return Promise.resolve(wallet.getPrivateKey().toString('hex'))
  }


  /* PRIVATE METHODS */

  _initFromMnemonic (mnemonic) {
    this.mnemonic = mnemonic
    const seed = braveCrypto.passphrase.toBytes32(mnemonic)
    this.hdWallet = hdkey.fromMasterSeed(seed)
    this.root = this.hdWallet.derivePath(this.hdPath)
  }

  /**
   * Inits wallet from a given 32-byte random seed.
   * @param {Uint8Array} seed
   */
  _initFromSeed (seed) {
    if (seed.byteLength !== 32) {
      throw new Error('Wallet seed is not 32 bytes.')
    }
    this.mnemonic = braveCrypto.passphrase.fromBytesOrHex(seed)
    this.hdWallet = hdkey.fromMasterSeed(seed)
    this.root = this.hdWallet.derivePath(this.hdPath)
  }

  _getWalletForAccount (account) {
    const targetAddress = sigUtil.normalize(account)
    return this.wallets.find((w) => {
      const address = sigUtil.normalize(w.getAddress().toString('hex'))
      return ((address === targetAddress) ||
              (sigUtil.normalize(address) === targetAddress))
    })
  }
}

HdKeyring.type = type
module.exports = HdKeyring
