'use strict'
const url = require('url')
const lib = require('@apigee/http-helper-functions')
const rLib = require('@apigee/response-helper-functions')

const PERMISSIONS_URL = process.env.PERMISSIONS_URL || ""

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
  function processResponse(clientRes) {
    lib.getClientResponseBody(clientRes, (body) => {
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
        rLib.internalError(res, {statusCode: clientRes.statusCode, msg: `failed to create permissions for ${resourceURL} statusCode ${clientRes.statusCode} message ${JSON.stringify(body)}`})
    })
  }
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
        return rLib.badRequest(res, 'value of _subject must match resourceURL')
      else if (permissions._inheritsPermissionsOf === undefined && (permissions._self === undefined || permissions._self.govern === undefined))
        return rLib.badRequest(res, `permissions for ${resourceURL} must specify inheritance or at least one governor`)
    }
    var postData = JSON.stringify(permissions)
    if (PERMISSIONS_URL !== "")
      lib.sendExternalRequestThen(res, 'POST', PERMISSIONS_URL + '/az-permissions',  flowThroughHeaders, postData, function (clientRes) {
        processResponse(clientRes)
      })
    else
      lib.sendInternalRequestThen(res, 'POST', '/az-permissions',  flowThroughHeaders, postData, function (clientRes) {
        processResponse(clientRes)
      })
  }
}

function createTeamThen(flowThroughHeaders, res, team, callback, errorCallback) {
  function processResponse(clientRes) {
    lib.getClientResponseBody(clientRes, (body) => {
      if (clientRes.statusCode == 201) {
        body = JSON.parse(body)
        lib.internalizeURLs(body, flowThroughHeaders.host)
        callback(clientRes.headers.location, body)
      } else if (errorCallback)
        errorCallback(clientRes.statusCode, body)
      else if (clientRes.statusCode == 400)
        rLib.badRequest(res, body)
      else if (clientRes.statusCode == 403)
        rLib.forbidden(res, `Forbidden. component: ${process.env.COMPONENT_NAME} unable to create team for ${team.name}.`)
      else if (clientRes.statusCode == 409)
        rLib.duplicate(res, body)
      else
        rLib.internalError(res, {statusCode: clientRes.statusCode, msg: `failed to create team for ${team.name} statusCode ${clientRes.statusCode} message ${JSON.stringify(body)}`})
    })
  }
  var user = lib.getUser(flowThroughHeaders.authorization)
  if (user == null)
    rLib.unauthorized(res)
  else {
    if (team === null || team === undefined)
      return rLib.badRequest(res, `may not set null permissions: ${resourceURL}`)
    var postData = JSON.stringify(team)
    if (PERMISSIONS_URL !== "")
      lib.sendExternalRequestThen(res, 'POST', PERMISSIONS_URL + '/az-teams',  flowThroughHeaders, postData, function (clientRes) {
        processResponse(clientRes)
      })
    else
      lib.sendInternalRequestThen(res, 'POST', '/az-teams',  flowThroughHeaders, postData, function (clientRes) {
        processResponse(clientRes)
      })
  }
}

function deletePermissionsThen(flowThroughHeaders, res, resourceURL, callback) {
  function processResponse(clientRes) {
    lib.getClientResponseBody(clientRes, (body) => {
      if (clientRes.statusCode == 200)
        callback()
      else
        rLib.internalError(res, `unable to delete permissions for ${resourceURL} statusCode: ${clientRes.statusCode} text: ${body}`)
    })
  }
  if (PERMISSIONS_URL !== "")
    lib.sendExternalRequestThen(res, 'DELETE', PERMISSIONS_URL + `/az-permissions?${resourceURL}`, flowThroughHeaders, undefined, function (clientRes) {
      processResponse(clientRes)
    })
  else
    lib.sendInternalRequestThen(res, 'DELETE', `/az-permissions?${resourceURL}`, flowThroughHeaders, undefined, function (clientRes) {
      processResponse(clientRes)
    })
}

function withAllowedDo(headers, res, resourceURL, property, action, base, path, callback, withScopes) {
  resourceURL = rLib.externalizeURLs(resourceURL)
  if (typeof base == 'function')
    [callback, base] = [base, callback] // swap them
  var user = lib.getUser(headers.authorization)
  var resourceURLs = Array.isArray(resourceURL) ? resourceURL : [resourceURL]
  var qs = resourceURLs.map(x => `resource=${x}`).join('&')
  var permissionsURL = `/az-is-allowed?${qs}`
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
  if (withScopes != null)
    permissionsURL += '&withScopes'
  function processResponse(clientRes, permissionsURL) {
    lib.getClientResponseBody(clientRes, (body) => {
      try {
        body = JSON.parse(body)
      } catch (e) {
        console.error('withAllowedDo: JSON parse failed. url:', permissionsURL, 'body:', body, 'error:', e)
      }
      var statusCode = clientRes.statusCode
      if (statusCode == 200)
        callback(body)
      else if (statusCode == 404)
        rLib.notFound(res, {msg: `Not Found. component: ${process.env.COMPONENT_NAME} permissionsURL: ${permissionsURL}`})
      else if (statusCode == 401)
        rLib.unauthorized(res, body)
      else if (statusCode == 403)
        rLib.forbidden(res, body)
      else
        rLib.internalError(res, `unable to retrieve withAllowedDo statusCode: ${statusCode} resourceURL: ${resourceURL} property: ${property} action: ${action} body: ${JSON.stringify(body)}`)
    })
  }
  if (PERMISSIONS_URL !== "")
    lib.sendExternalRequestThen(res, 'GET', PERMISSIONS_URL + permissionsURL, headers, undefined, function (clientRes) {
      processResponse(clientRes, PERMISSIONS_URL + permissionsURL)
    })
  else
    lib.sendInternalRequestThen(res, 'GET', permissionsURL, headers, undefined, function (clientRes) {
      processResponse(clientRes, permissionsURL)
    })
}

function ifAllowedThen(headers, res, resourceURL, property, action, base, path, callback, withScopes) {
  if (typeof base == 'function')
    [callback, withScopes, base] = [base, path, callback] // swap them
  withAllowedDo(headers, res, resourceURL, property, action, base, path, function(rslt) {
    if (withScopes ? rslt.allowed : rslt)
      callback(rslt)
    else
      if (lib.getUser(headers.authorization) !== null)
        rLib.forbidden(res, {msg: `Forbidden. component: ${process.env.COMPONENT_NAME} resourceURL: ${resourceURL} property: ${property} action: ${action} user: ${lib.getUser(headers.authorization)}`})
      else
        rLib.unauthorized(res)
  }, withScopes)
}

exports.Permissions = Permissions
exports.createPermissionsThen = createPermissionsThen
exports.deletePermissionsThen = deletePermissionsThen
exports.ifAllowedThen = ifAllowedThen
exports.withAllowedDo = withAllowedDo
exports.createTeamThen = createTeamThen

