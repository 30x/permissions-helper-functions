'use strict'
const url = require('url')
const lib = require('http-helper-functions')
const rLib = require('response-helper-functions')

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
            // The Node resolve implementation has a bug that causes URLs of the form http://authority#frag to get 
            // changed to http://authority/#frag (extra slash) so don't give the URL to resolve if it is a already an absolute URL
            permObject[action] = permObject[action].map(actor => actor.startsWith('http://') || actor.startsWith('https://') ? actor : url.resolve(baseURL, actor))
    }
}

function createPermissionsThen(flowThroughHeaders, res, resourceURL, permissions, callback, errorCallback) {
  var user = lib.getUser(flowThroughHeaders.authorization)
  if (user == null)
    rLib.unauthorized(res)
  else {
    if (permissions === null || permissions === undefined)
      rLib.badRequest(res, `may not set null permissions: ${resourceURL}`)
    else {
      if (permissions._subject === undefined)
        permissions._subject = resourceURL
      else if (permissions._subject != resourceURL)
        callback(400, 'value of _subject must match resourceURL')
      else if (permissions._inheritsPermissionsOf === undefined && (permissions._self === undefined || permissions._self.governs === undefined)) 
        rLib.badRequest(res, `permissions for ${resourceURL} must specify inheritance or at least one governor`)
    }
    var postData = JSON.stringify(permissions)
    lib.sendInternalRequestThen(res, 'POST','/permissions',  flowThroughHeaders, postData, function (clientRes) {
      lib.getClientResponseBody(clientRes, function(body) {
        if (clientRes.statusCode == 201) { 
          body = JSON.parse(body)
          lib.internalizeURLs(body, flowThroughHeaders.host)
          callback(null, clientRes.headers.location, body, clientRes.headers)
        } else if (errorCallback)
          errorCallback(clientRes.statusCode, body)
        else if (clientRes.statusCode == 400)
          rLib.badRequest(res, body)
        else if (clientRes.statusCode == 403)
          rLib.forbidden(res, `Forbidden. component: ${process.env.COMPONENT_NAME} unable to create permissions for ${permissions._subject}. You may not be allowed to inherit permissions from ${permissions._inheritsPermissionsOf}`)
        else if (clientRes.statusCode == 409)
          rLib.duplicate(res, body)
        else 
          rLib.internalError(res, {statusCode: clientRes.statusCode, msg: `failed to create permissions for ${resourceURL} statusCode ${clientRes.statusCode} message ${body}`})
      })
    })
  }
}

function deletePermissionsThen(flowThroughHeaders, res, resourceURL, callback) {
  lib.sendInternalRequestThen(res, 'DELETE', `/permissions?${resourceURL}`, flowThroughHeaders, undefined, function (clientRes) {
    lib.getClientResponseBody(clientRes, function(body) {
      var statusCode = clientRes.statusCode
      if (statusCode !== 200)
        rLib.internalError(res, `unable to delete permissions for ${resourceURL} statusCode: ${clientRes.statusCode} text: ${body}`)
    })
  })  
}

function withAllowedDo(headers, res, resourceURL, property, action, base, path, callback) {
  resourceURL = rLib.externalizeURLs(resourceURL)
  if (typeof base == 'function')
    [callback, base] = [base, callback] // swap them
  var user = lib.getUser(headers.authorization)
  var resourceURLs = Array.isArray(resourceURL) ? resourceURL : [resourceURL]
  var qs = resourceURLs.map(x => `resource=${x}`).join('&')
  var permissionsURL = `/is-allowed?${qs}`
  if (user != null)
    permissionsURL += '&user=' + user.replace('#', '%23')
  if (action != null)
    permissionsURL += '&action=' + action
  if (property != null)
    permissionsURL += '&property=' + property
  if (base != null)
    permissionsURL += '&base=' + base
  if (path != null)
    permissionsURL += '&path=' + path
  lib.sendInternalRequestThen(res, 'GET', permissionsURL, headers, undefined, function (clientRes) {
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
        rLib.notFound(res, `Not Found. component: ${process.env.COMPONENT_NAME} permissionsURL: ${permissionsURL}\n`)
      else
        rLib.internalError(res, `unable to retrieve withAllowedDo statusCode: ${statusCode} resourceURL: ${resourceURL} property: ${property} action: ${action} body: ${body}`)
    })
  })
}

function ifAllowedThen(headers, res, resourceURL, property, action, base, path, callback) {
  if (typeof base == 'function')
    [callback, base] = [base, callback] // swap them
  withAllowedDo(headers, res, resourceURL, property, action, base, path, function(allowed) {
    if (allowed === true)
      callback()
    else
      if (lib.getUser(headers.authorization) !== null) 
        rLib.forbidden(res, `Forbidden. component: ${process.env.COMPONENT_NAME} resourceURL: ${resourceURL} property: ${property} action: ${action} user: ${lib.getUser(headers.authorization)}\n`)
      else 
        rLib.unauthorized(res)
  })
}

exports.Permissions = Permissions
exports.createPermissionsThen = createPermissionsThen
exports.deletePermissionsThen = deletePermissionsThen
exports.ifAllowedThen = ifAllowedThen
exports.withAllowedDo = withAllowedDo