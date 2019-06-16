/* tslint:disable:no-bitwise */
import * as CryptoJS from 'crypto-js'
import * as URL from 'url'

/**
 * Defines an HTTP HMAC request signer.
 */
export class AcquiaHttpHmac {
  /**
   * Determines if a request will send a bodyString.
   */
  static willSendBody(method: string, body: string): boolean {
    return body.length !== 0 && ['GET', 'HEAD'].indexOf(method) < 0
  }

  /**
   * Generates the value for the X-Authorization-Timestamp header.
   */
  static generateAuthorizationTimestamp(): string {
    return Math.floor(Date.now() / 1000).toString()
  }

  /**
   * Generates the value for the X-Authorization-Content-SHA256 header.
   */
  static generateAuthorizationContentSha256(method: string, body: string) {
    if (!AcquiaHttpHmac.willSendBody(method, body)) {
      return ''
    }

    return CryptoJS.SHA256(body).toString(CryptoJS.enc.Base64)
  }

  private readonly config: any

  constructor({
                realm,
                public_key,
                secret_key,
                version = '2.0',
                default_content_type = 'application/json'
              }: {
    realm: string,
    public_key: string,
    secret_key: string,
    version: string,
    default_content_type: string
  }) {
    if (!realm) {
      throw new Error('The "realm" must not be empty.')
    }

    if (!public_key) {
      throw new Error('The "public_key" must not be empty.')
    }

    if (!secret_key) {
      throw new Error('The "secret_key" must not be empty.')
    }

    let supported_versions = ['2.0']

    if (supported_versions.indexOf(version) < 0) {
      throw new Error(`The version must be "${supported_versions.join('" or "')}". Version "${version}" is not supported.`)
    }

    let parsed_secret_key = CryptoJS.enc.Base64.parse(secret_key)
    this.config = {
      realm,
      public_key,
      parsed_secret_key,
      version,
      default_content_type
    }
  }

  /**
   * Generates the value for the Authorization header.
   */
  signHeaders({
    fullURL,
    httpMethod,
    bodyString = '',
    headers = {},
    content_type = this.config.default_content_type
  }: {
    fullURL: string,
    httpMethod: string,
    bodyString: string,
    headers: any,
    content_type: string
  }) {
    /**
     * Convert an object of parameters to a string.
     */
    let parametersToString = (parameters: any, value_prefix = '=', value_suffix = '', glue = '&', encode = true) => {
      let parameter_keys = Object.keys(parameters)
      let processed_parameter_keys: string[] = []
      let processed_parameters: any = {}
      let result_string_array: string[] = []

      // Process the headers.
      // 1) Process the parameter keys into lowercase, and
      // 2) Process values to URI encoded if applicable.
      parameter_keys.forEach(parameter_key => {
        if (!parameters.hasOwnProperty(parameter_key)) {
          return
        }
        let processed_parameter_key = parameter_key.toLowerCase()
        processed_parameter_keys.push(processed_parameter_key)
        processed_parameters[processed_parameter_key] = encode ? encodeURIComponent(parameters[parameter_key]) : parameters[parameter_key]
      })

      // Process into result string.
      processed_parameter_keys.sort().forEach(processed_parameter_key => {
        if (!processed_parameters.hasOwnProperty(processed_parameter_key)) {
          return
        }
        result_string_array.push(`${processed_parameter_key}${value_prefix}${processed_parameters[processed_parameter_key]}${value_suffix}`)
      })
      return result_string_array.join(glue)
    }

    /**
     * Generate a UUID nonce.
     */
    let generateNonce = () => {
      let d = Date.now()

      return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        let r = (d + Math.random() * 16) % 16 | 0
        d = Math.floor(d / 16)

        return (c === 'x' ? r : (r & 0x7 | 0x8)).toString(16)
      })
    }

    let timestamp = AcquiaHttpHmac.generateAuthorizationTimestamp()

    let parameters: any = {
      id: this.config.public_key,
      nonce: generateNonce(),
      realm: encodeURIComponent(this.config.realm),
      version: this.config.version
    }

    let url = URL.parse(fullURL)

    let signature = [
      httpMethod,
      url.port ? `${url.host}:${url.port}` : url.host,
      url.pathname,
      url.query
    ]

    signature.push(parametersToString(parameters))

    if (Object.keys(headers).length > 0) {
      signature.push(parametersToString(headers, ':', '', '\n', false))
      parameters.headers = encodeURIComponent(Object.keys(headers).join('|||||').toLowerCase().split('|||||').sort().join(''))
    } else {
      parameters.headers = ''
    }

    signature.push(timestamp)

    if (AcquiaHttpHmac.willSendBody(httpMethod, bodyString)) {
      signature.push(content_type)
      signature.push(AcquiaHttpHmac.generateAuthorizationContentSha256(httpMethod, bodyString))
    }

    let signatureString = signature.join('\n')

    parameters.signature = CryptoJS.HmacSHA256(signatureString, this.config.parsed_secret_key).toString(CryptoJS.enc.Base64)

    let authString = `acquia-http-hmac ${parametersToString(parameters, '="', '"', ',', false)}`

    let newHeaders: any = {
      Authorization: authString,
      // Authorization: this.signHeaders2(httpMethod, fullURL, headers, bodyString),
      'X-Authorization-Timestamp': timestamp,
      'Content-Type': 'application/json',
      Accept: '*/*'
    }

    if (AcquiaHttpHmac.willSendBody(httpMethod, bodyString)) {
      newHeaders['X-Authorization-Content-SHA256'] = AcquiaHttpHmac.generateAuthorizationContentSha256(httpMethod, bodyString)
    }

    return newHeaders
  }
}
