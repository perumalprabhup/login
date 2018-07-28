const express = require ('express');

const bodyParser = require ('body-parser');

const mongoose = require ('mongoose');

const Promotion = require('../models/promotion');

const authenticate = require ('../authenticate');

const cors = require ('./cors');

const promotionRouter = express.Router();

promotionRouter.use(bodyParser.json());

promotionRouter.route('/')
.options(cors.corsWithOptions,(req,res) =>{res.sendStatus(200);})

.get(cors.cors,(req,res,next)=>{
	Promotion.find(req.query)
		.then((promo)=>{
			
			res.status = 200;
			res.setHeader('Content-Type','application/json');
			res.json(promo);
				
		},(err)=>next(err)).catch((err)=>next(err));
		
})

.post(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next) => {
		
		Promotion.create(req.body)
		.then((promo) =>{
			
			console.log("Promotion Added ",promo);
			res.status = 200;
			res.setHeader('Content-Type','application/json');
			res.json(promo);
			
		},(err)=>next(err)).catch((err)=>next(err));
		

})
	
.put(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next) => {
	res.statusCode = 403;
	res.end('Put not Supported for Promotion');
})

.delete(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next)=>{
		
		Promotion.remove({})
			.then((promo) =>{
				
			res.status = 200;
			res.setHeader('Content-Type','application/json');
			res.json(promo);
			
	
		},(err)=>next(err)).catch((err)=>next(err));
		
	

});

promotionRouter.route('/:promoId')
.options(cors.corsWithOptions,(req,res) =>{res.sendStatus(200);})


.get(cors.cors,(req,res,next)=>{
	
	Promotion.findById(req.params.promoId)
	.then((promo)=>{
		
			res.status = 200;
			res.setHeader('Content-Type','application/json');
			res.json(promo);
			
	},(err)=>next(err)).catch((err)=>next(err));
		
	
})

.post(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next) => {
	res.statusCode = 403;
	res.end('Post will not supported for dishes '+ req.params.promoId);
})

.put(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next) => {
	
	Promotion.findByIdAndUpdate(req.params.promoId,{
		$set : req.body
	},{new :true})
	.then((promo)=>{
		
			res.status = 200;
			res.setHeader('Content-Type','application/json');
			res.json(promo);
			
	},(err)=>next(err)).catch((err)=>next(err));
})

.delete(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next)=>{
	Promotion.findByIdAndRemove(req.params.promoId)
	.then((promo)=>{
		
			res.status = 200;
			res.setHeader('Content-Type','application/json');
			res.json(promo);
			
	},(err)=>next(err)).catch((err)=>next(err));
})
module.exports = promotionRouter;

