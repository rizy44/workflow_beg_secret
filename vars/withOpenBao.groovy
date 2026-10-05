/**
 * withOpenBao: Jenkins Shared Library step.
 *
 * Fetches secrets from OpenBao (same Python stages as the GitHub Action), injects
 * them as environment variables for the body, masks them, and revokes the
 * OpenBao token when the body finishes (success or failure).
 *
 *   @Library('workflow-beg-secret') _
 *
 *   withOpenBao(
 *       url:           'https://openbao.example.com:8200',
 *       namespace:     'my-namespace',
 *       credentialsId: 'openbao-approle',        // Username with password: username=role_id, password=secret_id
 *       secrets: [
 *           'PATH=ci/artifactory,PREFIX=ARTIFACTORY_',
 *           'PATH=ci/dockerhub,KEYS=username|token,PREFIX=DOCKERHUB_',
 *       ]
 *   ) {
 *       sh './scripts/build.sh'                   // $ARTIFACTORY_API_KEY ... are set and masked
 *   }
 *
 * Options:
 *   url (required), credentialsId (required), secrets (required: List<String>)
 *   namespace      ''            OpenBao namespace
 *   mount          'kv/test'     secret engine mount
 *   kvVersion      '2'           1 or 2
 *   approleMount   'approle'
 *   maskPasswords  true          wrap the body with the Mask Passwords plugin
 *   python         'python3'     interpreter on the agent (>= 3.8, no pip packages needed)
 *   toolRepo       'https://github.com/rizy44/workflow_beg_secret.git'
 *   toolRef        'main'        branch/tag of the scripts checked out on the agent
 *   toolCredentialsId  null      only if toolRepo is private
 *
 * Plugins: Pipeline Utility Steps (readProperties), Credentials Binding, Git,
 * Mask Passwords (when maskPasswords: true).
 */
def call(Map config = [:], Closure body) {
    for (String key : ['url', 'credentialsId', 'secrets']) {
        if (!config[key]) {
            error("withOpenBao: '${key}' is required")
        }
    }
    List<String> secretSpecs = (config.secrets instanceof List) ? config.secrets : [config.secrets.toString()]

    String tmpDir = pwd(tmp: true)
    String toolDir = "${tmpDir}/workflow-beg-secret"
    String propsFile = "${tmpDir}/.openbao_env.${UUID.randomUUID().toString()}.properties"
    List<String> baoEnv = [
        "OPENBAO_URL=${config.url}",
        "OPENBAO_NAMESPACE=${config.namespace ?: ''}",
        "OPENBAO_CACERT=${config.cacert ?: ''}",
        "OPENBAO_TOOL_DIR=${toolDir}",
        "OPENBAO_PYTHON=${config.python ?: 'python3'}",
    ]

    // Stage 0: get the Python stages onto the agent (the library itself lives on the controller).
    dir(toolDir) {
        checkout(changelog: false, poll: false, scm: [
            $class: 'GitSCM',
            branches: [[name: config.toolRef ?: 'main']],
            userRemoteConfigs: [[
                url: config.toolRepo ?: 'https://github.com/rizy44/workflow_beg_secret.git',
                credentialsId: config.toolCredentialsId,
            ]],
        ])
    }

    // Stages 1-4: login, fetch, mask list, export to a temporary properties file.
    Map props = [:]
    try {
        withCredentials([usernamePassword(credentialsId: config.credentialsId,
                                          usernameVariable: 'OPENBAO_ROLE_ID',
                                          passwordVariable: 'OPENBAO_SECRET_ID')]) {
            withEnv(baoEnv + [
                "OPENBAO_MOUNT=${config.mount ?: 'kv/test'}",
                "OPENBAO_KV_VERSION=${config.kvVersion ?: '2'}",
                "OPENBAO_APPROLE_MOUNT=${config.approleMount ?: 'approle'}",
                "OPENBAO_SECRETS=${secretSpecs.join('\n')}",
                "OPENBAO_PROPS_FILE=${propsFile}",
            ]) {
                sh(label: 'OpenBao: fetch secrets', script: '''
                    "$OPENBAO_PYTHON" "$OPENBAO_TOOL_DIR/scripts/main.py" fetch --platform jenkins --output "$OPENBAO_PROPS_FILE"
                ''')
            }
        }
        props = readProperties(file: propsFile)
    } finally {
        // Delete immediately: the file must never reach the workspace archive.
        withEnv(["OPENBAO_PROPS_FILE=${propsFile}"]) {
            sh(label: 'OpenBao: delete temp file', script: 'rm -f "$OPENBAO_PROPS_FILE"')
        }
    }

    String token = props.remove('OPENBAO_TOKEN') ?: ''
    List<String> maskedNames = (props.remove('OPENBAO_MASKED_KEYS') ?: '').tokenize(',')
    List<String> secretEnv = []
    List<Map> maskPairs = []
    for (String name : props.keySet()) {
        secretEnv.add("${name}=${props[name]}".toString())
    }
    for (String name : maskedNames) {
        String value = (name == 'OPENBAO_TOKEN') ? token : props[name]
        if (value) {
            maskPairs.add([var: name, password: value])
        }
    }
    if (token) {
        secretEnv.add("OPENBAO_TOKEN=${token}".toString())
    }

    try {
        withEnv(secretEnv) {
            if (config.maskPasswords == false) {
                body()
            } else {
                wrap([$class: 'MaskPasswordsBuildWrapper', varPasswordPairs: maskPairs]) {
                    body()
                }
            }
        }
    } finally {
        // Stage 5: revoke the token whatever happened in the body.
        if (token) {
            withEnv(baoEnv + ["OPENBAO_TOKEN=${token}"]) {
                int rc = sh(label: 'OpenBao: revoke token', returnStatus: true, script: '''
                    "$OPENBAO_PYTHON" "$OPENBAO_TOOL_DIR/scripts/main.py" revoke
                ''')
                if (rc != 0) {
                    echo "withOpenBao: WARNING token revoke failed (rc=${rc}); it will expire with its TTL"
                }
            }
        }
        dir(toolDir) {
            deleteDir()
        }
    }
}
