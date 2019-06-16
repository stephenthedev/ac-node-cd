import {Command, flags} from '@oclif/command'
import ux, { cli } from 'cli-ux'
import * as request from 'request-promise-native'

import { AcquiaHttpHmac } from './api-hmac'

class AcNodeCd extends Command {
  static description = 'Deploy a just built node.js artifact from Acquia Pipelines'

  static flags = {
    version: flags.version({char: 'v'}),
    help: flags.help({char: 'h'}),
  }

  async run() {
    const API = 'https://cloud.acquia.com/api'
    const API_TOKEN = process.env.AC_API_TOKEN
    const API_SECRET = process.env.AC_API_SECRET
    const ENV_UUID = process.env.AC_DEPLOY_ENV_UUID
    const APP_UUID = process.env.PIPELINE_APPLICATION_ID
    const CURRENT_BRANCH = process.env.PIPELINE_VCS_PATH
    const CURRENT_HASH = process.env.PIPELINE_GIT_HEAD_REF

    let hmac = new AcquiaHttpHmac({
      realm: 'Acquia',
      public_key: API_TOKEN || 'foo',
      secret_key: API_SECRET || 'bar',
      version: '2.0',
      default_content_type: 'application/json'
    })

    let artifact

    try {
      const listURL = `${API}/applications/${APP_UUID}/artifacts?filter=name%3D${CURRENT_BRANCH}@${CURRENT_HASH}`
      const listArtifactResponse = await request.get({
        uri: listURL,
        headers: hmac.signHeaders({
          httpMethod: 'GET',
          fullURL: listURL,
          bodyString: '',
          headers: {},
          content_type: 'application/json'
        })
      })

      artifact = JSON.parse(listArtifactResponse)._embedded.items[0]
    } catch (e) {
      cli.warn('Could not list artifacts:' + e.message)
      cli.error('Failed to deploy node artifact.')
    }

    if (!artifact) {
      cli.error(`Could not find the artifact ${CURRENT_BRANCH}@${CURRENT_HASH}`)
    }
    try {
      const deployURL = `${API}/environments/${ENV_UUID}/artifacts/actions/switch`
      const deployBody = {artifact_id: artifact.id}
      await request.post({
        uri: deployURL,
        json: deployBody,
        headers: hmac.signHeaders({
          httpMethod: 'POST',
          fullURL: deployURL,
          bodyString: JSON.stringify(deployBody),
          headers: {},
          content_type: 'application/json'
        })
      })
    } catch (e) {
      cli.warn('Could not deploy artifact:' + e.message)
      cli.error('Failed to deploy node artifact.')
    }

    cli.log('Node.JS Artifact deployed to env:' + ENV_UUID)
  }
}

export = AcNodeCd
