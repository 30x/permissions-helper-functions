'use strict'
const url = require('url')
const lib = require('http-helper-functions')

function Permissions(permissions) {
  this.permissions = permissions
}

Permissions.prototype.resolveRelativeURLs = function(baseURL) {
  if (this.permissions._subject)
    this.permissions._subject = url.resolve(baseURL, this.permissions._subject)
  for (var property in this.permissions)
    if (['_metadata', '_subject', '_inheritsPermissionsOf'].indexOf(property) < 0) {
      var permObject = this.permissions[property]
      if (typeof permObject == 'object')
        for (var action in permObject)
          if (Array.isArray(permObject[action]))
            permObject[action] = permObject[action].map(actor => url.resolve(baseURL, actor))
    }
}

function createPermissionsThen(req, res, resourceURL, permissions, callback, errorCallback) {
  var flowThroughHeaders = req.headers
  var user = lib.getUser(flowThroughHeaders.authorization)
  if (user == null)
    lib.unauthorized(req, res)
  else {
    if (permissions === null || permissions === undefined)
      permissions = {
        _subject: resourceURL,
        _permissions: {
          read: [user],
          update: [user],
          delete: [user]
        },
        _self: {
          read: [user],
          delete: [user],
          update: [user],
          create: [user]
        }
      }
    else {
      if (permissions._subject === undefined)
        permissions._subject = resourceURL
      else
        if (permissions._subject != resourceURL)
          callback(400, 'value of _subject must match resourceURL')
      var permissionsPermissons = permissions._permissions
      if (permissions._inheritsPermissionsOf === undefined && (permissionsPermissons === undefined || permissionsPermissons.update === undefined)) {
        if (permissionsPermissons === undefined) 
          permissions._permissions = permissionsPermissons = {}
        permissionsPermissons.update = [user]
        permissionsPermissons.read = (permissions._self ? permissions._self.read: null) || [user]
      } 
    }
    var postData = JSON.stringify(permissions)
    lib.sendInternalRequestThen(req, res, '/permissions', 'POST', postData, function (clientRes) {
      lib.getClientResponseBody(clientRes, function(body) {
        if (clientRes.statusCode == 201) { 
          body = JSON.parse(body)
          lib.internalizeURLs(body, flowThroughHeaders.host)
          callback(null, clientRes.headers.location, body, clientRes.headers)
        } else if (errorCallback)
          errorCallback(clientRes.statusCode, body)
        else if (clientRes.statusCode == 400)
          lib.badRequest(res, body)
        else if (clientRes.statusCode == 403)
          lib.forbidden(req, res, `Forbidden. component: ${process.env.COMPONENT} unable to create permissions for ${permissions._subject}. You may not be allowed to inherit permissions from ${permissions._inheritsPermissionsOf}`)
        else if (clientRes.statusCode == 409)
          lib.duplicate(res, body)
        else 
          lib.internalError(res, {statusCode: clientRes.statusCode, msg: `failed to create permissions for ${resourceURL} statusCode ${clientRes.statusCode} message ${body}`})
      })
    })
  }
}

function withAllowedDo(req, res, resourceURL, property, action, base, path, callback) {
  resourceURL =  resourceURL || '//' + req.headers.host + req.url
  var user = lib.getUser(req.headers.authorization)
  var resourceURLs = Array.isArray(resourceURL) ? resourceURL : [resourceURL]
  var qs = resourceURLs.map(x => `resource=${x}`).join('&')
  var permissionsURL = `/is-allowed?${qs}`
  if (user !== null)
    permissionsURL += '&user=' + user.replace('#', '%23')
  if (action !== null)
    permissionsURL += '&action=' + action
  if (property !== null)
    permissionsURL += '&property=' + property
  if (base !== null)
    permissionsURL += '&base=' + base
  if (path !== null)
    permissionsURL += '&path=' + path
  lib.sendInternalRequestThen(req, res, permissionsURL, 'GET', undefined, function (clientRes) {
    lib.getClientResponseBody(clientRes, function(body) {
      try {
        body = JSON.parse(body)
      } catch (e) {
        console.error('withAllowedDo: JSON parse failed. url:', permissionsURL, 'body:', body, 'error:', e)
      }
      var statusCode = clientRes.statusCode
      if (statusCode == 200)
        callback(body)
      else if (statusCode == 404)
        lib.notFound(req, res, `Not Found. component: ${process.env.COMPONENT} permissionsURL: ${permissionsURL}\n`)
      else
        lib.internalError(res, `unable to retrieve withAllowedDo statusCode: ${statusCode} resourceURL: ${resourceURL} property: ${property} action: ${action} body: ${body}`)
    })
  })
}

function ifAllowedThen(req, res, resourceURL, property, action, base, path, callback) {
  if (typeof base == 'function')
    [callback, base] = [base, callback] // swap them
  withAllowedDo(req, res, resourceURL, property, action, base, path, function(allowed) {
    if (allowed === true)
      callback()
    else
      if (lib.getUser(req.headers.authorization) !== null) 
        lib.forbidden(req, res, `Forbidden. component: ${process.env.COMPONENT} resourceURL: ${resourceURL || '//' + req.headers.host + req.url} property: ${property} action: ${action} user: ${lib.getUser(req.headers.authorization)}\n`)
      else 
        lib.unauthorized(req, res)
  })
}

exports.Permissions = Permissions
exports.createPermissionsThen = createPermissionsThen
exports.ifAllowedThen = ifAllowedThen
exports.withAllowedDo = withAllowedDo