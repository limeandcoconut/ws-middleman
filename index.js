const { port } = require('./config.js')
const WebSocket = require('ws')
const argon2 = require('argon2')
const { jwtSecret } = require('./keys.js')
const JWT = require('./jwt.js')(jwtSecret)

const passwords = require('./password-hashes.js')
if (passwords.length === 0) {
  console.log('\u001B[41mWARNING: No passwords specified.\u001b[0m')
}

const ws = new WebSocket.Server({ port })

const codes = {
  400: {
    code: 400,
    error: 'Invalid request',
  },
  401: {
    code: 401,
    error: 'Unauthorized',
  },
  502: {
    code: 502,
    error: 'Unreachable',
  },
}

let freeId = 0
const getId = () => freeId++

const sockets = {}

const getAuthReply = () => ({
  // Generate a token that's good for 30 minutes
  jwt: JWT.encode({ exp: Date.now() + (30 * 60 * 1000) }),
})

const authenticate = async ({ password }, socket) => {
  for (const record of passwords) {
    if (!await argon2.verify(record, password)) {
      continue
    }
    sockets.api = socket
    return {
      type: 'auth',
      data: getAuthReply(),
    }
  }
  return codes[401]
}

const send = (id, reply) => {
  const socket = sockets[id]
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    console.log(`Error: connection to ${id} not open`)
    return
  }

  if (reply.error) {
    socket.send(JSON.stringify({
      type: 'error',
      data: reply,
    }))
    return
  }

  socket.send(JSON.stringify(reply))
  return
}

ws.on('connection', async (socket) => {
  console.log(socket)
  socket.on('message', async (message) => {
    let { type, jwt, id, data = {}, apiJWT, role } = JSON.parse(message)

    console.log(type, data, jwt)

    // If it's an api:
    if (role === 'api') {
      if (sockets.api) {
        send(400)
        return
      }
      if (type === 'auth') {
        send(id, await authenticate(data, socket))
        return
      }
      if (!apiJWT) {
        send(id, codes[401])
        return
      }
      const decoded = JWT.decode(apiJWT)
      if (!decoded || decoded.exp < Date.now()) {
        send(id, codes[401])
        return
      }
      if (type === 'reauth') {
        send(id, getAuthReply())
        return
      }
      if (type === 'broadcast') {
        // Broadcast to all connected clients but the api
        ws.clients.forEach((client) => {
          if (client === sockets.api) {
            return
          }
          client.send(JSON.stringify({
            type: 'update',
            data,
          }))
        })
        return
      }
      if (typeof id === 'undefined') {
        send(id, codes[400])
        return
      }
      send(id, { type, jwt, id, data })
      return
    }

    // If it's a consumer:

    // If the consumer is unknown id it
    if (typeof id === 'undefined') {
      id = getId()
      message.id = id
      sockets[id] = socket
    }
    // If there's no api tunnel
    if (!sockets.api) {
      // Only respond direcly if there's no gateway
      send(id, codes[502])
      return
    }
    // Pass message to api
    sockets.api.send(message)
    return
  })

  socket.on('close', () => {
    sockets[socket.id] = null
  })
})
