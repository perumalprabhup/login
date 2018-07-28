const mongoose = require('mongoose');
const Schema = mongoose.Schema;

require('mongoose-currency').loadType(mongoose);
var Currency = mongoose.Types.Currency;

var feedbackSchema = new Schema({
    
    author:  {
        
		type: String,
        required: true
    
	},
	rating :{
		
		type : String,
		required : true
		
	}
}, {
    timestamps: true
});

var leaderSchema = new Schema({
    name: {
        type: String,
        required: true,
        unique: true
    },
    description: {
        type: String,
        required: true
    },
	designation: {
        type: String,
        required: true
    },
    image: {
        type: String,
        required: true
    },
	abbr: {
        type: String,
        required: true
    },
	featured:{
		type : Boolean,
		default : false
	},
    feedbacks:[feedbackSchema]
},  {
    timestamps: true
});


var Leader = mongoose.model('Leader', leaderSchema);

module.exports = Leader;