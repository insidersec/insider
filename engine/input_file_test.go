package engine_test

import (
	"path/filepath"
	"testing"

	"github.com/insidersec/insider/engine"
	"github.com/stretchr/testify/assert"
)

func TestNewInputFileJava(t *testing.T) {
	content := []byte(
		`
package br.com.foo.bar;
import java.util.Calendar;
import java.util.Date;

public class MyMainClass {
	public static void main(String[] args) {
	System.out.println("Hello World!");
	}
}
		`,
	)
	filename := "src/foo/bar/main.java"
	dir := "src/foo/bar"

	input, err := engine.NewInputFileWithContent(dir, filename, content)

	assert.Nil(t, err, "Expected nil error to create input file")
	assert.Equal(t, filename, input.PhysicalPath, "Expected equal PhysicalPath")
	assert.Equal(t, string(content), input.Content, "Expected equal content")
	assert.Equal(t, "main.java", input.DisplayName, "Expected equal DisplayName")
	assert.Equal(t, "main.java", input.Name, "Expected equal Name")

}

func TestNewInputFileJavaScript(t *testing.T) {
	content := []byte(
		`
const express = require('express');
const logger = require('morgan');
require('dotenv').config({path : path.resolve(__dirname, 'config','dev.env')});
const fileUpload = require('express-fileupload')
// Set up the express app
const app = express();
app.use(express.json({limit: '50mb'}));

// Log requests to the console.
app.use(logger('dev'));


const router = express.Router();
require('./routes/api/v1/auth')(router);
require('./routes/api/v1/company')(router);
require('./routes/api/v1/user')(router);
require('./routes/api/v1/userrole')(router);
app.use('/core/api/v1', router)

app.get('/', function (req, res) {
  res.status(200).json({message:'OK'});
});

if(process.env.NODE_ENV=="production"){
  var errorHandler = function(err, req, res, next){
    res.status(500).json({message:"Error internal server"})
  };
  app.use(errorHandler);
}
module.exports = app;
		`,
	)
	filename := "src/foo/bar/baz/main.js"
	dir := "src/foo/bar"

	input, err := engine.NewInputFileWithContent(dir, filename, content)

	assert.Nil(t, err, "Expected nil error to create input file")
	assert.Equal(t, filename, input.PhysicalPath, "Expected equal PhysicalPath")
	assert.Equal(t, string(content), input.Content, "Expected equal content")
	assert.Equal(t, filepath.Join("baz", "main.js"), input.DisplayName, "Expected equal DisplayName")
	assert.Equal(t, "main.js", input.Name, "Expected equal Name")

}
