/**
 * Created by dob on 14.04.14.
 */
var assert = require('assert'),
  user = require('../'),
  util = require('util'),
  EventEmitter = require('events').EventEmitter,
  should = require('should'),
  mlcl_database = require('mlcl_database'),
  mlcl_elastic = require('mlcl_elastic'),
  mlcl_elements = require('mlcl_elements');

describe('url', function(){
  //var mytestobject;
  var mlcl;
  var molecuel;
  var mongo;
  var elastic;

  before(function (done) {
    mlcl = function() {
      return this;
    };
    util.inherits(mlcl, EventEmitter);
    molecuel = new mlcl();

    molecuel.config = { };
    molecuel.config.search = {
      hosts: ['http://localhost:9200'],
      prefix: 'mlcl-user-unit'
    };
    molecuel.config.database = {
      type: 'mongodb',
      uri: 'mongodb://localhost/mlcl-user-unit'
    };
    molecuel.config.user = {
      secret: 'test2342'
    };
    molecuel.config.elements = {
      schemaDir: __dirname + '/definitions'
    };
    mongo = mlcl_database(molecuel);
    elastic = mlcl_elastic(molecuel);
    done();
  });

  describe('user', function () {
    it('should be a function', function () {
      assert('function' === typeof user);
    });
  });

  describe('molecuel user', function() {
    var searchcon;
    var dbcon;
    //var testmodel;
    var elements;
    var u;

    before(function(){
      u = new user(molecuel);
    });

    it('should initialize db connection', function(done) {
      molecuel.once('mlcl::database::connection:success', function(database) {
        dbcon = database;
        database.should.be.a.object;
        done();
      });
      molecuel.emit('mlcl::core::init:post', molecuel);
    });

    it('should initialize search connection', function(done) {
      molecuel.once('mlcl::search::connection:success', function(search) {
        searchcon = search;
        search.should.be.a.object;
        done();
      });
      molecuel.emit('mlcl::core::init:post', molecuel);
    });

    it('should construct elements module', function(done) {
      molecuel.once('mlcl::elements::init:pre', function(module) {
        module.should.be.a.object;
        done();
      });
      elements = new mlcl_elements(molecuel);
    });

    it('should finalize elements registrations', function(done) {
      molecuel.once('mlcl::elements::init:post', function(module) {
        module.should.be.a.object;
        done();
      });
      molecuel.emit('mlcl::database::connection:success', dbcon);
      molecuel.emit('mlcl::search::connection:success', searchcon);
    });

    it('should have registered user model', function(done) {
      assert('function' === typeof elements.modelRegistry['user']);
      done();
    });

    it('should have registered the field references of the user model in page model', function(done) {
      elements.modelRegistry['page'].schema.paths['lastchangedby'].should.be.an.Object;
      elements.modelRegistry['page'].schema.paths['createdby'].should.be.an.Object;
      done();
    });

    after(function(done) {
      searchcon.deleteIndex('*', function() {
        done();
      });
    });
  });
});