var createError = require('http-errors');
var express = require('express');
var path = require('path');
//var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require ('express-session');
var FileStore = require ('session-file-store')(session);

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var dishRouter = require('./routes/dishRouter');
var leaderRouter = require('./routes/leaderRouter');
var promotionRouter = require('./routes/promotionRouter');
var uploadRouter = require('./routes/uploadRouter');
var favoriteRouter = require('./routes/favouriteRouter');
var config = require('./config');

var mongoose = require ('mongoose');
mongoose.Promise =require ('bluebird');
 
var Dishes = require ('./models/dishes');
var Promotion = require ('./models/promotion');
var Leader = require('./models/leader');

var passport = require('passport');
var authenticate = require('./authenticate');

var url = config.mongoUrl;

var connect = mongoose.connect(url);

connect.then((db) =>{
	console.log('Connected to the server Properly');
	
},(err) => {console.log(err);});

var app = express();
/*
app.all('*', (req,res,next) => {
	
	if(req.secure){
		
		return next();	
	}
	else{
	
		res.redirect(307, 'https://'+ req.hostname +':'+app.get('secPort')+req.url);	
	}
	
});
*/
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(passport.initialize());

app.use('/', indexRouter);
app.use('/users', usersRouter);

app.use(express.static(path.join(__dirname, 'public')));


app.use('/dishes',dishRouter);
app.use('/promotion',promotionRouter);
app.use('/leader',leaderRouter);
app.use('/imageUpload',uploadRouter);
app.use('/favorites',favoriteRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});
// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  // render the error page
  res.status(err.status || 500);
  res.render('error');
});
module.exports = app;




/*

app.use('/dishes',dishRouter);
app.use('/promotion',promotionRouter);
app.use('/leader',leaderRouter);
app.use('/upload',uploadRouter);
app.use('/favorites',favoriteRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});
// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  // render the error page
  res.status(err.status || 500);
  res.render('error');
});
module.exports = app;

*/
