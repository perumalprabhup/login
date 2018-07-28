const mongoose = require('mongoose');
const Schema = mongoose.Schema;

require('mongoose-currency').loadType(mongoose);
var Currency = mongoose.Types.Currency;


var promotionSchema = new Schema({
    name: {
        type: String,
        required: true,
        unique: true
    },
    image: {
        type: String,
        required: true
    },
	label: {
        type: String,
        default: ''
    },
	price: {
        type: Currency,
		min :0,
		required: true
    },
	featured:{
		type : Boolean,
		default : false
	},
    description: {
        type: String,
        required: true
    }
},  {
    timestamps: true
});


var Promotion = mongoose.model('Promo', promotionSchema);

module.exports = Promotion;