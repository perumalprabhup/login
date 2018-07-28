const mongoose = require('mongoose');
const Schema = mongoose.Schema;
var passportLocalMongoose = require('passport-local-mongoose');


var user = new Schema({

	firstname:{
		type : String,
		default : ''
	},
	lastname:{
		type : String,
		default : ''
	},
	facebookId: String,
	admin : {
		
		type : Boolean,
		default : false
		
	}
	
}, {
    timestamps: true
});
user.plugin(passportLocalMongoose);


var User = mongoose.model('User', user);


module.exports = User;