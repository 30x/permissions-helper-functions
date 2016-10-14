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
    if (['_metadata', '_subject', '_sharedWith', '_inheritsPermissionsOf', 'test-data'].indexOf(property) < 0) {
      var permObject = this.permissions[property]
      for (var action in permObject)
        permObject[action] = permObject[action].map(actor => url.resolve(baseURL, actor))
    }
}

function createPermissionsFor(flowThroughHeaders, resourceURL, permissions, callback) {
  var user = lib.getUser(flowThroughHeaders.authorization)
  if (user == null)
    callback(401)
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
    lib.sendInternalRequest(flowThroughHeaders, '/permissions', 'POST', postData, function (err, clientRes) {
      if (err)
        callback(500, err)
      else
        lib.getClientResponseBody(clientRes, function(body) {
          if (clientRes.statusCode == 201) { 
            body = JSON.parse(body)
            lib.internalizeURLs(body, flowThroughHeaders.host)
            callback(null, clientRes.headers.location, body, clientRes.headers)
          } else if (clientRes.statusCode == 400)
            callback(400, body)
          else if (clientRes.statusCode == 403)
            callback(403)
          else if (clientRes.statusCode == 409)
            callback(409)
          else {
            var err = {statusCode: clientRes.statusCode,
              msg: `failed to create permissions for ${resourceURL} statusCode ${clientRes.statusCode} message ${body}`
            }
            callback(500, err)
          }
        })
    })
  }
}

function createPermissionsThen(req, res, resourceURL, permissions, callback) {
  resourceURL = resourceURL || `//${req.host}/${req.url}`
  var flowThroughHeaders = req.headers
  createPermissionsFor(flowThroughHeaders, resourceURL, permissions, function(err, permissionsURL, permissions, headers) {
    if (err == 500)
      lib.internalError(res, permissionsURL)
    else if (err == 400)
      lib.badRequest(res, body)
    else if (err == 403)
      lib.forbidden(req, res)
    else if (err == 409)
      lib.duplicate(res, body)
    else if (err)
      lib.internalError(res, `failed to create permissions for ${resourceURL} err: ${err} message ${permissionsURL}`)
    else
      callback(permissionsURL, permissions)
  })
}

function withAllowedDo(flowThroughHeaders, resourceURL, property, action, callback) {
  var user = lib.getUser(flowThroughHeaders.authorization)
  var resourceURLs = Array.isArray(resourceURL) ? resourceURL : [resourceURL]
  var qs = resourceURLs.map(x => `resource=${x}`).join('&')
  var permissionsURL = `/is-allowed?${qs}`
  if (user !== null)
    permissionsURL += '&user=' + user.replace('#', '%23')
  if (action !== null)
    permissionsURL += '&action=' + action
  if (property !== null)
    permissionsURL += '&property=' + property
  lib.sendInternalRequest(flowThroughHeaders, permissionsURL, 'GET', undefined, function (err, clientRes) {
    if (err)
      callback(500, err)
    else
      lib.getClientResponseBody(clientRes, function(body) {
        try {
          body = JSON.parse(body)
        } catch (e) {
          console.error('withAllowedDo: JSON parse failed. url:', permissionsURL, 'body:', body, 'error:', e)
        }
        callback(null, clientRes.statusCode, body)
      })
  })
}

function ifAllowedThen(flowThroughHeaders, resourceURL, property, action, callback) {
  //resourceURL =  resourceURL || '//' + req.headers.host + req.url
  withAllowedDo(flowThroughHeaders, resourceURL, property, action, function(err, statusCode, allowed) {
    if (err)
      callback(err)
    else if (statusCode == 200)
      if (allowed === true)
        callback()
      else
        if (lib.getUser(flowThroughHeaders.authorization) !== null)
          callback(403)
        else 
          callback(401)
    else if (statusCode == 404)
      callback(404)
    else
      callback(500, `unable to retrieve withAllowedDo statusCode: ${statusCode} resourceURL: ${resourceURL} property: ${property} action: ${action}`)
  })
}

exports.Permissions = Permissions
exports.createPermissionsFor = createPermissionsFor
exports.createPermissionsThen = createPermissionsThen
exports.ifAllowedThen = ifAllowedThen
exports.withAllowedDo = withAllowedDo