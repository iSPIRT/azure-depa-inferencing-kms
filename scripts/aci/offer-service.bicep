param containerName string = 'offer-service'
param containerImage string = 'kapilvaswani/bidding-service:nonprod-4.3.0.0'
param cpuCores int = 2
param memoryInGb int = 4
param location string = resourceGroup().location

resource offerContainer 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: containerName
  location: location
  properties: {
    containers: [
      {
        name: containerName
        properties: {
          image: containerImage
          ports: [
            {
              port: 50057
              protocol: 'TCP'
            }
          ]
          resources: {
            requests: {
              cpu: cpuCores
              memoryInGb: memoryInGb
            }
          }
          environmentVariables: [
            { name: 'BIDDING_HEALTHCHECK_PORT', value: '50551' }
            { name: 'BIDDING_PORT', value: '50057' }
            { name: 'BIDDING_TCMALLOC_BACKGROUND_RELEASE_RATE_BYTES_PER_SECOND', value: '4096' }
            { name: 'BIDDING_TCMALLOC_MAX_TOTAL_THREAD_CACHE_BYTES', value: '10737418240' }
            { name: 'BUYER_CODE_FETCH_CONFIG', value: '{"fetchMode":0,"biddingJsPath":"","biddingJsUrl":"https://raw.githubusercontent.com/KenGordon/bidding-auction-servers/refs/heads/kapilv/generate-bid/fetchAdditionalSignals.js","protectedAppSignalsBiddingJsUrl":"https://raw.githubusercontent.com/KenGordon/bidding-auction-servers/refs/heads/kapilv/generate-bid/fetchAdditionalSignals.js","biddingWasmHelperUrl":"","protectedAppSignalsBiddingWasmHelperUrl":"","urlFetchPeriodMs":13000000,"urlFetchTimeoutMs":120000,"enableBuyerDebugUrlGeneration":true,"enableAdtechCodeLogging":true,"prepareDataForAdsRetrievalJsUrl":"","prepareDataForAdsRetrievalWasmHelperUrl":""}' }
            { name: 'EGRESS_SCHEMA_FETCH_CONFIG', value: '{"fetchMode":0,"egressSchemaUrl":"https://example.com/egressSchema.json","urlFetchPeriodMs":130000,"urlFetchTimeoutMs":30000}' }
            { name: 'BFE_INGRESS_TLS', value: '' }
            { name: 'BFE_TCMALLOC_BACKGROUND_RELEASE_RATE_BYTES_PER_SECOND', value: '4096' }
            { name: 'BFE_TCMALLOC_MAX_TOTAL_THREAD_CACHE_BYTES', value: '10737418240' }
            { name: 'BFE_TLS_CERT', value: '' }
            { name: 'BFE_TLS_KEY', value: '' }
            { name: 'BIDDING_EGRESS_TLS', value: '' }
            { name: 'BIDDING_SERVER_ADDR', value: 'offer-service.ad_selection.microsoft:50057' }
            { name: 'BIDDING_SIGNALS_LOAD_TIMEOUT_MS', value: '60000' }
            { name: 'BUYER_FRONTEND_HEALTHCHECK_PORT', value: '50552' }
            { name: 'BUYER_FRONTEND_PORT', value: '50051' }
            { name: 'BUYER_KV_SERVER_ADDR', value: 'kv.ad_selection.microsoft:50051' }
            { name: 'ENABLE_TKV_V2', value: 'true' }
            { name: 'TKV_EGRESS_TLS', value: 'false' }
            { name: 'BYOS_AD_RETRIEVAL_SERVER', value: 'false' }
            { name: 'CREATE_NEW_EVENT_ENGINE', value: 'false' }
            { name: 'ENABLE_BIDDING_COMPRESSION', value: 'false' }
            { name: 'ENABLE_BUYER_FRONTEND_BENCHMARKING', value: 'false' }
            { name: 'GENERATE_BID_TIMEOUT_MS', value: '60000' }
            { name: 'GRPC_ARG_DEFAULT_AUTHORITY', value: '' }
            { name: 'PROTECTED_APP_SIGNALS_GENERATE_BID_TIMEOUT_MS', value: '60000' }
            { name: 'KV_PORT', value: '50051' }
            { name: 'KV_HEALTHCHECK_PORT', value: '50051' }
            { name: 'AZURE_LOCAL_DATA_DIR', value: '/data/deltas' }
            { name: 'AZURE_LOCAL_REALTIME_DATA_DIR', value: '/data/realtime' }
            { name: 'AD_RETRIEVAL_KV_SERVER_ADDR', value: '' }
            { name: 'AD_RETRIEVAL_KV_SERVER_EGRESS_TLS', value: '' }
            { name: 'AD_RETRIEVAL_TIMEOUT_MS', value: '60000' }
            { name: 'BUYER_EGRESS_TLS', value: '' }
            { name: 'COLLECTOR_ENDPOINT', value: 'otel-collector-service.ad_selection.microsoft:4317' }
            { name: 'CONSENTED_DEBUG_TOKEN', value: 'test-token' }
            { name: 'ENABLE_AUCTION_COMPRESSION', value: 'false' }
            { name: 'ENABLE_BUYER_COMPRESSION', value: 'false' }
            { name: 'ENABLE_CHAFFING', value: 'false' }
            { name: 'ENABLE_OTEL_BASED_LOGGING', value: 'false' }
            { name: 'ENABLE_PROTECTED_APP_SIGNALS', value: 'false' }
            { name: 'INFERENCE_MODEL_BUCKET_NAME', value: '' }
            { name: 'INFERENCE_MODEL_BUCKET_PATHS', value: '' }
            { name: 'INFERENCE_MODEL_CONFIG_PATH', value: '' }
            { name: 'INFERENCE_MODEL_FETCH_PERIOD_MS', value: '60000' }
            { name: 'INFERENCE_MODEL_LOCAL_PATHS', value: '' }
            { name: 'INFERENCE_SIDECAR_BINARY_PATH', value: '' }
            { name: 'K_ANONYMITY_SERVER_ADDR', value: '' }
            { name: 'K_ANONYMITY_SERVER_TIMEOUT_MS', value: '60000' }
            { name: 'KV_SERVER_EGRESS_TLS', value: '' }
            { name: 'MAX_ALLOWED_SIZE_DEBUG_URL_BYTES', value: '65536' }
            { name: 'MAX_ALLOWED_SIZE_ALL_DEBUG_URLS_KB', value: '3000' }
            { name: 'PS_VERBOSITY', value: '10' }
            { name: 'ROMA_TIMEOUT_MS', value: '' }
            { name: 'SELECTION_KV_SERVER_ADDR', value: '' }
            { name: 'SELECTION_KV_SERVER_EGRESS_TLS', value: '' }
            { name: 'SELECTION_KV_SERVER_TIMEOUT_MS', value: '60000' }
            { name: 'TEE_AD_RETRIEVAL_KV_SERVER_ADDR', value: '' }
            { name: 'TEE_KV_SERVER_ADDR', value: 'kv.ad_selection.microsoft:50051' }
            { name: 'TELEMETRY_CONFIG', value: 'mode: EXPERIMENT' }
              { name: 'AZURE_BA_PARAM_GET_TOKEN_URL', value: 'http://169.254.169.254/metadata/identity/oauth2/token' }
              { name: 'AZURE_BA_PARAM_KMS_UNWRAP_URL', value: 'https://depa-inferencing-kms.centralindia.cloudapp.azure.com/app/unwrapKey?fmt=tink' }
              { name: 'ENABLE_PROTECTED_AUDIENCE', value: 'true' }
              { name: 'KEY_REFRESH_FLOW_RUN_FREQUENCY_SECONDS', value: '10800' }
              { name: 'PRIMARY_COORDINATOR_ACCOUNT_IDENTITY', value: '' }
              { name: 'PRIMARY_COORDINATOR_PRIVATE_KEY_ENDPOINT', value: 'https://depa-inferencing-kms.centralindia.cloudapp.azure.com/app/key?fmt=tink' }
              { name: 'PRIMARY_COORDINATOR_REGION', value: '' }
              { name: 'PRIVATE_KEY_CACHE_TTL_SECONDS', value: '3888000' }
              { name: 'PUBLIC_KEY_ENDPOINT', value: 'https://depa-inferencing-kms.centralindia.cloudapp.azure.com/app/listpubkeys' }
              { name: 'SFE_PUBLIC_KEYS_ENDPOINTS', value: '{"AZURE":"https://depa-inferencing-kms.centralindia.cloudapp.azure.com/app/listpubkeys"}' }
              { name: 'TEST_MODE', value: 'false' }
          ]
        }
      }
    ]
    osType: 'Linux'
    restartPolicy: 'Always'
    sku: 'Confidential'
    ipAddress: {
      type: 'Public'
      ports: [
        {
          protocol: 'TCP'
          port: 50057
        }
      ]
    }
    confidentialComputeProperties: {
      ccePolicy: loadTextContent('allow_all.base64')
    }
  }
}
