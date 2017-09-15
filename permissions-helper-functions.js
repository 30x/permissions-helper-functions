'use strict'
const url = require('url')
const lib = require('@apigee/http-helper-functions')
const rLib = require('@apigee/response-helper-functions')

const PERMISSIONS_BASE = process.env.PERMISSIONS_BASE || ""

function permissionsServiceUrl(possiblyRelativeURL) {
  if (PERMISSIONS_BASE)
    return url.resolve(PERMISSIONS_BASE, possiblyRelativeURL)
  else
    return possiblyRelativeURL
}
  
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
      rLib.badRequest(res, {msg: 'may not set null permissions', resource: resourceURL})
    else {
      if (permissions._subject === undefined)
        permissions._subject = resourceURL
      else if (permissions._subject != resourceURL)
        return rLib.badRequest(res, 'value of _subject must match resourceURL')
      else if (permissions._inheritsPermissionsOf === undefined && (permissions._self === undefined || permissions._self.govern === undefined))
        return rLib.badRequest(res, `permissions for ${resourceURL} must specify inheritance or at least one governor`)
    }
    var postData = JSON.stringify(permissions)
    lib.sendInternalRequestThen(res, 'POST', permissionsServiceUrl('/az-permissions'),  flowThroughHeaders, postData, function (clientRes) {
      lib.getClientResponseObject(res, clientRes, null, (body) => {
        if (clientRes.statusCode == 201) {
          lib.internalizeURLs(body, flowThroughHeaders.host)
          callback(null, clientRes.headers.location, body, clientRes.headers)
        } else if (errorCallback)
          errorCallback(clientRes.statusCode, body)
        else if (clientRes.statusCode == 400)
          rLib.badRequest(res, body)
        else if (clientRes.statusCode == 403)
          rLib.forbidden(res, {
            msg:'Forbidden. Unable to create permissions. You may not be allowed to inherit permissions from sharingSets', 
            component: process.env.COMPONENT_NAME, 
            subject: permissions._subject, 
            sharingSets: permissions._inheritsPermissionsOf, 
            user: user
          })
        else if (clientRes.statusCode == 409)
          rLib.duplicate(res, body)
        else
          rLib.internalError(res, {statusCode: clientRes.statusCode, msg: 'permissions-helper-function::createPermissionsThen failed to create permissions', resource: resourceURL, statusCode: clientRes.statusCode, body: body, permissionsUrl:  permissionsServiceUrl(`/az-permissions?${resourceURL}`)})
      })
    })
  }
}

function createTeamThen(flowThroughHeaders, res, team, callback, errorCallback) {
  var user = lib.getUser(flowThroughHeaders.authorization)
  if (user == null)
    rLib.unauthorized(res)
  else {
    if (team === null || team === undefined)
      return rLib.badRequest(res, `may not set null permissions: ${resourceURL}`)
    var postData = JSON.stringify(team)
    console.log('\n\n', permissionsServiceUrl('/az-teams'), '\n\n')
    lib.sendInternalRequestThen(res, 'POST', permissionsServiceUrl('/az-teams'),  flowThroughHeaders, postData, function (clientRes) {
      lib.getClientResponseObject(res, clientRes, null, (body) => {
        if (clientRes.statusCode == 201) {
          lib.internalizeURLs(body, flowThroughHeaders.host)
          callback(clientRes.headers.location, body)
        } else if (errorCallback)
          errorCallback(clientRes.statusCode, body)
        else if (clientRes.statusCode == 400)
          rLib.badRequest(res, body)
        else if (clientRes.statusCode == 403)
          rLib.forbidden(res, {msg: 'Forbidden. unable to create team', component: process.env.COMPONENT_NAME, reason: body})
        else if (clientRes.statusCode == 409)
          rLib.duplicate(res, body)
        else
          rLib.internalError(res, {statusCode: clientRes.statusCode, msg: 'permissions-helper-functions::createTeamThen failed to create team', body: body})
      })
    })
  }
}

function deletePermissionsThen(flowThroughHeaders, res, resourceURL, callback) {
  lib.sendInternalRequestThen(res, 'DELETE', permissionsServiceUrl(`/az-permissions?${resourceURL}`), flowThroughHeaders, undefined, function (clientRes) {
    lib.getClientResponseBody(clientRes, (body) => {
      if (clientRes.statusCode == 200)
        callback()
      else
        rLib.internalError(res, `unable to delete permissions for ${resourceURL} statusCode: ${clientRes.statusCode} text: ${body}`)
    })
  })
}

function deleteTeamThen(flowThroughHeaders, res, resourceURL, callback) {
  lib.sendInternalRequestThen(res, 'DELETE', permissionsServiceUrl(resourceURL), flowThroughHeaders, undefined, function (clientRes) {
    lib.getClientResponseBody(clientRes, (body) => {
      if (clientRes.statusCode == 200)
        callback()
      else
        rLib.internalError(res, `unable to delete team ${resourceURL} statusCode: ${clientRes.statusCode} text: ${body}`)
    })
  })
}

function createEntryThen(flowThroughHeaders, res, entry, callback) {
  lib.postToInternalResourceThen(res, permissionsServiceUrl('/dir-entries'), flowThroughHeaders, entry, callback)
}

function withDirectoryEntryDo(flowThroughHeaders, res, path, callback) {
  let searchUrl = permissionsServiceUrl(`/dir-entries?${path}`)
  lib.withInternalResourceDo(res, searchUrl, flowThroughHeaders, callback)
}

function deleteEntryThen(flowThroughHeaders, res, directory, name, resource, callback) {
  if (!directory)
    return rLib.internalError(res, {msg: 'permissions-helper-functions::deleteEntryThen must provide directory and name or directory and resource', directory: directory, name: name, resource: resource})
  let qs = `directory=${directory}`
  if (name)
    qs += `&name=${name}`
  else if (resource)
    qs += `&resource=${resource}`
  else
    return rLib.internalError(res, {msg: 'permissions-helper-functions::deleteEntryThen must provide directory and name or directory and resource', directory: directory, name: name, resource: resource})
  let searchUrl = permissionsServiceUrl(`/dir-entries?${qs}`)
  lib.withInternalResourceDo(res, searchUrl, flowThroughHeaders, callback)
}

function withAllowedDo(headers, res, resourceURL, property, action, base, path, callback, withScopes) {
  resourceURL = rLib.externalizeURLs(resourceURL)
  if (typeof base == 'function')
    [callback, base] = [base, callback] // swap them
  var user = lib.getUser(headers.authorization)
  var resourceURLs = Array.isArray(resourceURL) ? resourceURL : [resourceURL]
  var qs = resourceURLs.map(x => `resource=${x}`).join('&')
  var permissionsUrl = `/az-is-allowed?${qs}`
  if (user != null)
    permissionsUrl += '&user=' + user.replace('#', '%23')
  if (action != null)
    permissionsUrl += '&action=' + action
  if (property != null)
    permissionsUrl += '&property=' + property
  if (base != null)
    permissionsUrl += '&base=' + base
  if (path != null)
    permissionsUrl += '&path=' + path
  if (withScopes != null)
    permissionsUrl += '&withScopes'
  permissionsUrl = permissionsServiceUrl(permissionsUrl) 
  lib.sendInternalRequestThen(res, 'GET', permissionsUrl, headers, undefined, function (clientRes) {
    lib.getClientResponseBody(clientRes, (body) => {
      try {
        body = JSON.parse(body)
      } catch (e) {
        console.error('withAllowedDo: JSON parse failed. url:', permissionsUrl, 'body:', body, 'error:', e)
      }
      var statusCode = clientRes.statusCode
      if (statusCode == 200)
        callback(body)
      else if (statusCode == 404)
        rLib.notFound(res, {msg: `Not Found. component: ${process.env.COMPONENT_NAME} permissionsUrl: ${permissionsUrl}`})
      else if (statusCode == 401)
        rLib.unauthorized(res, body)
      else if (statusCode == 403)
        rLib.forbidden(res, body)
      else
        rLib.internalError(res, `unable to retrieve withAllowedDo statusCode: ${statusCode} resourceURL: ${resourceURL} property: ${property} action: ${action} body: ${JSON.stringify(body)}`)
    })
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
exports.deleteTeamThen = deleteTeamThen
exports.createEntryThen = createEntryThen
exports.deleteEntryThen = deleteEntryThen
exports.withDirectoryEntryDo = withDirectoryEntryDo
