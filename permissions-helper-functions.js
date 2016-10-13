'use strict'
const url = require('url')

function Permissions(permissions) {
  this.permissions = permissions
}

Permissions.prototype.resolveRelativeURLs = function(baseURL) {
  this.permissions._subject = url.resolve(baseURL, this.permissions._subject)
  for (var property in this.permissions)
    if (['_metadata', '_subject', '_sharedWith'].indexOf(property) < 0) {
      var permObject = this.permissions[property]
      for (var action in permObject) 
        permObject[action] = permObject[action].map(actor => url.resolve(baseURL, actor))
    }
}

exports.Permissions = Permissions