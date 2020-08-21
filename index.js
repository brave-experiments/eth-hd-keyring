const EventEmitter = require('events').EventEmitter
const hdkey = require('ethereumjs-wallet/hdkey')
const Wallet = require('ethereumjs-wallet')
const SimpleKeyring = require('eth-simple-keyring')
const bip39 = require('bip39')
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')
const braveCrypto = require('brave-crypto')

// Options:
const hdPathString = `m/44'/60'/0'/0`
const type = 'HD Key Tree'

const uint8ToArrayBuf = (array) => {
  return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
}
const bufToUint8Array = (buf) => {
  return new Uint8Array(buf)
}

class HdKeyring extends SimpleKeyring {

  /* PUBLIC METHODS */
  constructor (opts = {}) {
    super()
    this.type = type
    this.deserialize(opts)
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

  serialize () {
    return Promise.resolve({
      mnemonic: this.mnemonic,
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath,
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

  /* PRIVATE METHODS */

  _initFromSeed (seed) {
    if (seed.byteLength !== 32) {
      throw new Error('Wallet seed is not 32 bytes.')
    }
    this.mnemonic = braveCrypto.passphrase.fromBytesOrHex(seed)
    this.hdWallet = hdkey.fromMasterSeed(seed)
    this.root = this.hdWallet.derivePath(this.hdPath)
  }

  _initFromMnemonic (mnemonic) {
    this.mnemonic = mnemonic
    let seed
    try {
      seed = braveCrypto.passphrase.toBytes32(mnemonic)
    } catch (e) {
      // Support metamask word restoration
      console.warn('Could not get seed using brave-crypto.')
      seed = bip39.mnemonicToSeed(mnemonic)
    }
    this.hdWallet = hdkey.fromMasterSeed(seed)
    this.root = this.hdWallet.derivePath(this.hdPath)
    // return seed for testing
    return seed
  }
}

HdKeyring.type = type
module.exports = HdKeyring

