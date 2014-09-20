var _ = require('underscore');
var bcrypt = require('bcrypt');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var jwt = require('jsonwebtoken');  //https://npmjs.org/package/node-jsonwebtoken
var async = require('async');

var molecuel;
var elements;

/**
 * This module serves user database element
 * @todo implement dynamic user authentication registration.
 * @constructor
 */


var user = function() {
  var self = this;

  // Add libraries
  this.jwt = jwt;

  // secret
  this.secret = molecuel.config.user.secret;

  //  define default roles
  var roles = ['admin','editor'];
  // check if there are roles defined by the configuration of the current project
  if(molecuel.config && molecuel.config.user && molecuel.config.user.roles) {
    roles = molecuel.config.user.roles;
  }

  // Definition of the user schema
  this.userSchema =  {
    // Definition of the username
    username: { type: String, list: true, required: true, trim: true, unique: true, index: true },
    // Define the email address
    email: { type: String, list: true, trim: true, lowercase: true, required: true},

    // save the date and time of the last login
    lastlogin: { type: Date, 'default': Date.now, form: {readonly: true}},
    // save date and time of the last logon error
    lasterror: { type: Date, form: {readonly: true}},
    // save the creation date of the user
    creation: { type: Date, 'default': Date.now, form: {readonly: true}},
    // count the visits of the user
    visits: {type: Number, 'default': 0, form: {readonly: true}},

    // Password
    // these two fields are fake fields only and will be deleted
    password: {type: String},
    passwordConfirmation: {type: String, form:{ secure: true}},

    // password save
    salt: { type: String, required: true, form: {hidden:true }},
    hash: { type: String, required: true, form: {hidden: true}},

    name: {
      first: { type: String, required: false, trim: true },
      last: { type: String, required: false, trim: true }
    },
    authtype: {type: String, 'default': 'local'},
    active: { type: Boolean, 'default': true, index: true},
    roles: [{
      type: String,
      enum: roles,
      required: false,
      form:{
        formStyle: 'inline',
        placeHolder: 'Select roles'
      }
    }]
  };

  molecuel.once('mlcl::elements::registrations:pre', function(module) {
    elements = module;
    // module == elements module
    var schemaDefinition = {
      schemaName: 'user',
      schema: self.userSchema,
      options: {indexable: true, avoidTranslate: true, avoidUrl: true}
    };
    elements.registerSchemaDefinition(schemaDefinition);
  });

  // on elements registration of user schema
  molecuel.on('mlcl::elements::registerSchema:post::user', function(module, schemaRegistryEntry) {
    self.schema = schemaRegistryEntry.schema;
    //module.addToBaseSchema({createdby: {type: elements.ObjectId, ref: 'user', form:{hidden:true}}});
    self.schema.plugin(self._registerDefaultschemaFunctions);
  });

  // schema registration event
  molecuel.on('mlcl::elements::registerSchema:post', function(module, schemaname, schemaRegistryEntry) {
    schemaRegistryEntry.schema.plugin(self._defaultSchemaPlugin);
  });

  molecuel.on('mlcl::elements::setElementType:post::user', function(module, model) {
    self.model = model;
    self._registerDefaultPassportFunctions(model);
  });

  molecuel.once('mlcl::elements::init:post', function(elements) {
    elements.registerPostApiHandler(self._postApiHandler);
  });
  return this;
};

/*************************************************************************
 SINGLETON CLASS DEFINITION
 *************************************************************************/
var instance = null;

/**
 * Singleton getInstance definition
 * @return singleton class
 */
var getInstance = function () {
  if (instance === null) {
    instance = new user();
  }
  return instance;
};

user.prototype.middleware = function middleware(config, app) {
  if(molecuel.config && molecuel.config.user.secret) {
    app.use(passport.initialize());
    app.use(getInstance().initUser);
    app.post('/login/jwt', passport.authenticate('local', { session: false }), getInstance().userLogin);
  }
};

/**
 * Middleware function to register the current user on the request
 * @todo: Is this the right place?
 * @param req
 * @param res
 * @param next
 */
user.prototype.initUser = function(req, res, next) {
  if(req.headers.authorization) {
    jwt.verify(req.headers.authorization, molecuel.config.user.secret, function(err, decoded) {
      if(err && !decoded) {
        next();
      } else {
        req.user = decoded;
        next();
      }
    });
  } else {
    next();
  }
};

/**
 * userLogin - description
 *
 * @param  {type} req description
 * @param  {type} res description
 * @return {type}     description
 */
user.prototype.userLogin = function userLogin(req, res) {
  // We are sending the profile inside the token
  var expiresInMinutes = 60*4;
  // Check if there is a session expiration defined
  if(molecuel.config.user && molecuel.config.user.session_expiration) {
    expiresInMinutes = molecuel.config.user.session_expiration;
  }
  var token = jwt.sign(JSON.parse(JSON.stringify(req.user)), molecuel.config.user.secret, { expiresInMinutes: expiresInMinutes });
  res.json({name: user.name, _id: user._id, username: user.username, email: user.email, token: token });
};

user.prototype.debugHeader = function debugHeader(req, res, next) {
  console.log(req.headers);
  console.log(req.body);
  next();
};

/**
 * Default schema extend
 * @param schema
 * @private
 */
user.prototype._defaultSchemaPlugin = function _defaultSchemaPlugin(schema) {
  schema.add({
    createdby: {
      type: elements.ObjectId,
      ref: 'user',
      form: {readonly: true, label: 'Created by'}
    },
    lastchangedby: {
      type: elements.ObjectId,
      ref: 'user',
      form: {readonly: true, label: 'Last changed by'}
    }
  });
};

/**
 * Register the default functions used for local authentication
 * @param schema
 */
user.prototype._registerDefaultschemaFunctions = function(schema) {
  schema.pre('validate', function(next) {
    if (this.password && this.passwordConfirmation) {
      var invalid = false;
      if (! elements.validator.isLength(this.password, 6)) {
        this.invalidate('password', 'must be at least 6 characters.');
        invalid = true;
      }

      if (this.password !== this.passwordConfirmation) {
        this.invalidate('passwordConfirmation', 'must match confirmation.');
        invalid = true;
      }

      if(!invalid) {
        this.salt = bcrypt.genSaltSync(10);
        this.hash = bcrypt.hashSync(this.password, this.salt);
      }
    }
    next();
  });

  schema.pre('save', function(next) {
    this.password = undefined;
    this.passwordConfirmation = undefined;
    next();
  });

  schema.method('checkPassword', function (password, callback) {
    if(this.hash) {
      bcrypt.compare(password, this.hash, callback);
    } else {
      callback(null, false);
    }
  });

  schema.static('authenticate', function (username, password, callback) {
    var self = this;
    this.findOne({ username: username }, function(err, user) {
      if (err) {
        return callback(err);
      }

      if (!user) {
        return callback(null , false, { message: 'Unknown user'});
      }

      if(!user.active || user.active === false) {
        return callback(null , false, { message: 'User not activated' });
      }

      user.checkPassword(password, function(err, passwordCorrect) {
        if (err) {
          return callback(err);
        }

        if (!passwordCorrect) {
          var cond = {_id: user._id},
            upd = {$set: {lasterror: new Date()}},
            opt = {multi: false};
          self.update(cond, upd, opt, function() {
            return callback(null, false, {message: 'Wrong password'});
          });
        } else {
          var conditions = {_id: user._id},
            update = {$inc: {visits: 1}, $set: {lastlogin: new Date()}},
            options = {multi: false};

          self.update(conditions, update, options, function(err) {
            if(!err) {
              return callback(null, user);
            } else {
              return callback(null, false, {message: 'Error while updating user information'});
            }
          });
        }
      });
    });
  });
};

/**
 * Register the default functions for passport authentication
 * @param model
 * @private
 */
user.prototype._registerDefaultPassportFunctions = function _registerDefaultPassportFunctions(model) {

  passport.use(new LocalStrategy({
      usernameField: 'username'
    },
    function(username, password, done) {
      model.authenticate(username, password, function(err, user, msg) {
        return done(err, user, msg);
      });
    }
  ));

  /**
   * unused / no session implemented yet
   * We are using JWT
   */
    //Passport session setup.
  passport.serializeUser(function(user, done) {
    done(null, user._id);
  });

  /**
   * unused / no session implemented yet
   * We are using JWT
   */
  passport.deserializeUser(function(id, done) {
    //User.findById(id, {name: true, lastlogin: true},function (err, user) {
    var query = getInstance().model.findById(id);
    query.exec(function (err, user) {
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      } else {
        return done(null, user);
      }
    });
  });
};

/**
 * _getRoles
 * @returns {string[]}
 * @private
 * Return all the roles
 */
user.prototype._getRoles = function _getRoles() {
  //  define default roles
  var roles = ['admin','editor'];
  // check if there are roles defined by the configuration of the current project
  if(molecuel.config && molecuel.config.user && molecuel.config.user.roles) {
    roles = molecuel.config.user.roles;
  }
  return roles;
};

user.prototype._getPermissions = function _getPermissions(role) {
  if(role) {
    return molecuel.config.user.permissions[role];
  }
  return molecuel.config.user.permissions;
};

user.prototype._checkRole = function _checkRole(role, permission) {
  var allowed = _.contains(this._getPermissions(role), permission);
  return allowed;
};

/**
 * Register the function to act as middleware between API post and mongo save function
 * @param doc
 * @param req
 * @param callback
 * @private
 */
user.prototype._postApiHandler = function(doc, req, callback) {
  //var user = getInstance();
  if(req.user) {
    if(!doc.createdby) {
      doc.createdby = req.user._id; //mongoose creates ObjectIDs Cast errors if object reference is a simple object
    }
    doc.lastchangedby = req.user._id;
    callback();
  }  else {
    callback(new Error('No valid user found'));
  }
};


/**
 * Middleware function to check if the user has the correct permissions
 * @param item
 * @param req
 * @param res
 * @param next
 */
user.prototype.checkPermission = function checkPermission(item, req, res, next) {
  var self = this;
  this.jwt.verify(req.headers.authorization, this.secret, function(err, decoded) {
    if(err && !decoded) {
      if(err.name === 'TokenExpiredError') {
        res.send(401, 'Session expired');
      } else {
        res.send(401);
      }
    } else {
      self.model.findOne({_id: decoded._id}, function(err, doc) {
        if(doc && doc.active) {
          // set user object to request object
          req.user = decoded;
          var permission = item.permission;
          var detectPermission = function(role, callback) {
            if(self._checkRole(role, permission)) {
              callback(role);
            } else {
              callback();
            }
          };
          async.detect(doc.roles, detectPermission, function(result){
            if(result) {
              next();
            } else {
              res.send(401);
            }
          });
        } else {
          res.send(401);
        }
      });
    }
  });
};

/*
 user.prototype.getUserById = function getUserById(id) {

 };*/

var init = function (m) {
  // store molecuel instance
  molecuel = m;
  return getInstance();
};

module.exports = init;
