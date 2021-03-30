const { port } = require('./config.js')
const WebSocket = require('ws')
const argon2 = require('argon2')
const { jwtSecret } = require('./keys.js')
const JWT = require('./jwt.js')(jwtSecret)

let hashedPassword = require('./password-hashes.js')
if (!hashedPassword) {
  console.log('\u001B[41mWARNING: No passwords specified.\u001b[0m')
}
hashedPassword = hashedPassword[0]

// eslint-disable-next-line require-jsdoc
function log() {
  if (process.env.VERBOSE) {
    console.log(arguments)
  }
}

const ws = new WebSocket.Server({ port })

const codes = {
  400: {
    type: 'error',
    code: 400,
    error: 'Invalid request',
  },
  401: {
    type: 'error',
    code: 401,
    error: 'Unauthorized',
  },
  502: {
    type: 'error',
    code: 502,
    error: 'Unreachable',
  },
}

let freeId = 0
const getId = () => freeId++

const sockets = {}

// Set up heartbeat to keep connection open
const getHeartbeat = socket => () => {
  socket.isAlive = true
}

const getAuthReply = () => ({
  type: 'apiAuth',
  // Only the api can authenticate
  role: 'middleman',
  data: {
    // Generate a token that's good for 30 minutes
    jwt: JWT.encode({ exp: Date.now() + (30 * 60 * 1000) }),
  },
})

const authenticate = async ({ password }, socket) => {
  // If there's already an api registered or if the password is invalid 401
  if (sockets.api || !await argon2.verify(hashedPassword, password)) {
    return {
      ...codes[401],
      role: 'middleman',
    }
  }
  // Register the api and id it
  sockets.api = socket
  socket.id = 'api'

  log('API Authenticated')

  return getAuthReply()
}

// Send to a socket
const send = (id, reply, socket = sockets[id]) => {
  // If the socket is closed, error
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    console.log(`Error: connection to ${id} not open`)
    return
  }

  log('Sent: ', reply)

  // Construct an error and include role
  if (reply.error) {
    socket.send(JSON.stringify({
      type: 'error',
      role: reply.role,
      data: {
        code: reply.code,
        error: reply.error,
      },
    }))
    return
  }

  // Send successful message
  socket.send(JSON.stringify(reply))
}

ws.on('connection', async (socket) => {
  log('New Connection')

  // When the server recieves an connection tag it and set up a heartbeat
  socket.isAlive = true
  socket.on('pong', getHeartbeat(socket))

  socket.on('message', async (message) => {
    let { type, jwt, id, data = {}, apiJWT, role } = JSON.parse(message)
    log('Incoming: ', { type, jwt, id, data, apiJWT, role })

    // If it's an api:
    if (role === 'api') {
      // Respond to the api directly:
      if (type === 'apiAuth') {
        send('api', await authenticate(data, socket), socket)
        return
      }
      if (!apiJWT) {
        send('api', {
          ...codes[401],
          role: 'middleman',
        })
        return
      }
      const decoded = JWT.decode(apiJWT)
      if (!decoded || decoded.exp < Date.now()) {
        send('api', {
          ...codes[401],
          role: 'middleman',
        })
        return
      }
      if (type === 'apiReauth') {
        send('api', getAuthReply())
        return
      }
      // Send to consumer(s):
      if (type === 'update') {
        // Broadcast to all connected clients but the api
        message = JSON.stringify({
          type: 'update',
          data,
        })
        ws.clients.forEach((client) => {
          if (client !== sockets.api) {
            client.send(message)
          }
        })
        return
      }
      if (typeof id === 'undefined') {
        // 400 because there's no id for the consumer
        send(id, codes[400])
        return
      }
      // Send message along to consumer
      send(id, { type, jwt, id, data })
      return
    }

    // If it's a consumer:

    // If the consumer is unknown id it
    if (typeof id !== 'number') {
      id = getId()
      sockets[id] = socket
      socket.id = id
      log('Consumer registerd: ', id)
    }
    // Only respond direcly if there's no gateway
    if (!sockets.api) {
      send(id, codes[502])
      return
    }
    // Pass message to api
    message = JSON.stringify({
      type,
      jwt,
      id,
      data,
    })
    log('Sent: ', {
      type,
      jwt,
      id,
      data,
    })
    sockets.api.send(message)
    return
  })

  socket.on('close', () => {
    sockets[socket.id] = null
    log('Closed: ', socket.id)
  })
})

setInterval(() => {
  ws.clients.forEach((socket) => {
    if (socket.isAlive === false) {
      socket.terminate()
      return
    }

    socket.isAlive = false
    // WS spec requires a pong response
    socket.ping(() => {})
  })
  // Keep this timeout in sync with haproxy's settings
  // Haproxy is currently configred for a 1h timeout
}, 30 * 60 * 1000)
