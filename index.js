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

const getHeartbeat = socket => () => {
  socket.isAlive = true
}

const getAuthReply = () => ({
  type: 'apiAuth',
  role: 'api',
  data: {
    // Generate a token that's good for 30 minutes
    jwt: JWT.encode({ exp: Date.now() + (30 * 60 * 1000) }),
  },
})

const authenticate = async ({ password }, socket) => {
  if (sockets.api || !await argon2.verify(hashedPassword, password)) {
    return {
      ...codes[401],
      role: 'api',
    }
  }
  sockets.api = socket
  socket.id = 'api'
  return getAuthReply()
}

const send = (id, reply, socket = sockets[id]) => {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    console.log(`Error: connection to ${id} not open`)
    return
  }
  console.log('sent', reply)

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

  socket.send(JSON.stringify(reply))
  return
}

ws.on('connection', async (socket) => {
  console.log('CONNECTION:')
  console.log(socket.id)

  socket.isAlive = true
  socket.on('pong', getHeartbeat(socket))

  socket.on('message', async (message) => {
    let { type, jwt, id, data = {}, apiJWT, role } = JSON.parse(message)
    console.log(type, jwt, id, data, apiJWT, role)

    // If it's an api:
    if (role === 'api') {
      // Respond to the api:
      if (type === 'apiAuth') {
        send('api', await authenticate(data, socket), socket)
        return
      }
      if (!apiJWT) {
        send('api', {
          ...codes[401],
          role,
        })
        return
      }
      const decoded = JWT.decode(apiJWT)
      if (!decoded || decoded.exp < Date.now()) {
        send('api', {
          ...codes[401],
          role,
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
        send(id, codes[400])
        return
      }
      send(id, { type, jwt, id, data })
      return
    }

    // If it's a consumer:

    // If the consumer is unknown id it
    if (typeof id !== 'number') {
      id = getId()
      sockets[id] = socket
      socket.id = id
    }
    // If there's no api tunnel
    if (!sockets.api) {
      // Only respond direcly if there's no gateway
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
    console.log(message)
    sockets[id].send(message)
    return
  })

  socket.on('close', () => {
    sockets[socket.id] = null
  })
})

setInterval(() => {
  ws.clients.forEach((socket) => {
    if (socket.isAlive === false) {
      socket.terminate()
      return
    }

    socket.isAlive = false
    socket.ping(() => {})
  })
}, 9000)
