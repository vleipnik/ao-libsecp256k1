import * as MuClient from './client/ao-mu.js'
import * as CuClient from './client/ao-cu.js'
import * as GatewayClient from './client/gateway.js'
import * as WarpGatewayClient from './client/warp-gateway.js'
import * as IrysClient from './client/irys.js'

import { createLogger } from './logger.js'

import { readStateWith } from './lib/readState/index.js'
import { writeInteractionWith } from './lib/writeInteraction/index.js'
import { createContractWith } from './lib/createContract/index.js'

const WARP_GATEWAY_URL = globalThis.WARP_GATEWAY_URL || 'https://gw.warp.cc'
const IRYS_NODE = globalThis.IRYS_NODE || globalThis.BUNDLR_NODE || 'node2'
const GATEWAY_URL = globalThis.GATEWAY || 'https://arweave.net'
const MU_URL = globalThis.MU_URL || 'https://ao-mu-1.onrender.com'
const CU_URL = globalThis.CU_URL || 'https://ao-cu-1.onrender.com'

/**
 * Any environment specific build-time dependencies
 * can eventually be passed here (currently, there are none)
 *
 * Some dependencies, like the signer, are passed at runtime
 */
export function buildSdk () {
  const logger = createLogger('@permaweb/ao-sdk')

  const readStateLogger = logger.child('readState')
  const readState = readStateWith({
    loadState: CuClient.loadStateWith({ fetch, CU_URL, logger: readStateLogger }),
    logger: readStateLogger
  })

  /**
   * default writeInteraction that works OOTB
   * - writes signed data item for interaction to the MU
   */
  const writeInteractionLogger = logger.child('writeInteraction')
  const writeInteraction = writeInteractionWith({
    loadTransactionMeta: GatewayClient.loadTransactionMetaWith({ fetch, GATEWAY_URL }),
    deployInteraction: MuClient.deployInteractionWith({ fetch, MU_URL, logger: writeInteractionLogger }),
    logger: writeInteractionLogger
  })

  /**
   * default createContract that works OOTB
   * - Verifies the inputs
   * - Creates the contract
   *   - In browser, uses Arweave Wallet to upload contracts to Irys (via dispatch)
   *   - On server, uses Irys Node to upload contracts to Irys
   * - Registers the Contract with Warp
   */
  const createContractLogger = logger.child('createContract')
  const createContract = createContractWith({
    loadTransactionMeta: GatewayClient.loadTransactionMetaWith({ fetch, GATEWAY_URL }),
    deployContract: IrysClient.deployContractWith({ fetch, IRYS_NODE, logger }),
    registerContract: WarpGatewayClient.registerContractWith({ fetch, WARP_GATEWAY_URL, IRYS_NODE, logger: createContractLogger }),
    logger: createContractLogger
  })

  return { readState, writeInteraction, createContract }
}
