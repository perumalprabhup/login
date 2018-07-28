const express = require ('express');

const bodyParser = require ('body-parser');

const mongoose = require('mongoose');

const Leaders = require('../models/leader');
var authenticate = require('../authenticate');
const cors = require('./cors');

const leaderRouter = express.Router();

leaderRouter.use(bodyParser.json());

leaderRouter.route('/')
.options(cors.corsWithOptions,(req,res) =>{res.sendStatus(200);})

.get(cors.cors,(req,res,next)=>{

 Leaders.find(req.query)
	.then((leader)=>{
	
		res.status = 200;
		res.setHeader('Content-Type','application/json');
		res.json(leader);
	
	},(err)=>next(err))
	.catch((err)=>next(err));
	
})

.post(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next) => {

	Leaders.create(req.body)
	.then((leader)=>{
	
		console.log('Leader Created',leader);
		res.status = 200;
		res.setHeader('Content-Type','application/json');
		res.json(leader);
	
	},(err)=>next(err))
	.catch((err)=>next(err));
	
})
	
.put(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next) => {
	res.statusCode = 403;
	res.end('Put not Supported for Leaders so no Updation');
})

.delete(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next)=>{
	Leaders.remove({})
	.then((leader)=>{
	
		res.status = 200;
		res.setHeader('Content-Type','application/json');
		res.json(leader);
	
	},(err)=>next(err))
	.catch((err)=>next(err));
	
});

leaderRouter.route('/:leaderId')

.options(cors.corsWithOptions,(req,res) =>{res.sendStatus(200);})

.get(cors.cors,(req,res,next)=>{

Leaders.findById(req.params.leaderId)
	.then((leader)=>{
	
		res.status = 200;
		res.setHeader('Content-Type','application/json');
		res.json(leader);
	
	},(err)=>next(err))
	.catch((err)=>next(err));
	})

.post(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next) => {
	res.statusCode = 403;
	res.end('Post will not supported for Leaders '+ req.params.leaderId);
})

.put(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next) => {
	
	Leaders.findByIdAndUpdate(req.params.leaderId,{
		
		$set : req.body
	}
	,{new : true})
		
		.then((leader)=>{
	
		res.status = 200;
		res.setHeader('Content-Type','application/json');
		res.json(leader);
	
	},(err)=>next(err))
	.catch((err)=>next(err));
	})

.delete(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next)=>{
	Leaders.findByIdAndRemove(req.params.leaderId)
	.then((leader)=>{
	
		res.status = 200;
		res.setHeader('Content-Type','application/json');
		res.json(leader);
	
	},(err)=>next(err))
	.catch((err)=>next(err));
	});
	

leaderRouter.route('/:leaderId/feedbacks')

.options(cors.corsWithOptions,(req,res) =>{res.sendStatus(200);})

.get(cors.cors,(req,res,next)=>{

 Leaders.findById(req.params.leaderId)
	.then((leader)=>{
		
		if(leader != null){
			
		res.status = 200;
		res.setHeader('Content-Type','application/json');
		res.json(leader.feedbacks);
		
		}
		
		else {
			
			err = new Error ('Leader '+ req.params.leaderId +' not Found');
			res.statusCode = 404;
			return next(err);
		}
	},(err)=>next(err))
	.catch((err)=>next(err));
	
})

.post(cors.corsWithOptions,authenticate.verifyUser,(req,res,next) => {

	Leaders.findById(req.params.leaderId)
	.then((leader)=>{
		if(leader != null){
			leader.feedbacks.push(req.body);
			leader.save()
			.then((leader)=>{

			Leaders.findById(leader._id)
			.populate(feedbacks.author)
			.then((leader)=>{
				res.status = 200;
				res.setHeader('Content-Type','application/json');
				res.json(leader);
			})
		
		},(err)=>next(err))
		.catch((err)=>next(err))
		}
		else {
			err = new Error ('Leader '+ req.params.leaderId +' not Found');
			res.statusCode = 404;
			return next(err);
		}
	},(err)=>next(err))
	.catch((err)=>next(err));
	
	
})
	
.put(cors.corsWithOptions,authenticate.verifyUser,(req,res,next) => {
	res.statusCode = 403;
	res.end('Put not Supported for Leaders so no Updation');
})

.delete(cors.corsWithOptions,authenticate.verifyUser,authenticate.verifyAdmin,(req,res,next)=>{
	Leaders.findById(req.params.leaderId)
	.then((leader)=>{
		if(leader!=null){
			for (var i=(leader.feedbacks.length - 1); i >= 0 ; i--){
				leader.feedbacks.id(leader.feedbacks[i]._id).remove();
			}
			leader.save()
			.then((leader)=>{
				res.statusCode = 200;
				res.setHeader('Content-Type','application/json');
				res.json(leader);
			},(err) => next(err));
		}
	else{
		
		err = new Error('Leader '+ req.params.leaderId+" not found");
		res.statusCode = 404;
		return next(err);

		}	
	},(err)=>next(err))
	.catch((err)=>next(err));
	
});

leaderRouter.route('/:leaderId/feedbacks/:feedbackId')

.options(cors.corsWithOptions,(req,res) =>{res.sendStatus(200);})

.get(cors.cors,(req,res,next)=>{

 Leaders.findById(req.params.leaderId)
.then((leader)=>{
	if(leader != null && leader.feedbacks.id(req.params.feedbackId) != null){
	res.statusCode = 200;
	res.setHeader('Content-Type','application/json');
	res.json(leader.feedbacks.id(req.params.feedbackId));	
	}
	else if( leader == null){
		
		err = new Error ('Leader '+ req.params.leaderId +" not found");
		err.status = 404;
		return next(err);
		
	}
	else{
		
		err = new Error ('Feedback with ID : '+ req.params.feedbackId +" not found");
		err.status = 404;
		return next(err);
		
	}
	
	},(err)=>next(err)).catch((err)=>next(err));
})

.post(cors.corsWithOptions,authenticate.verifyUser,(req,res,next) => {
	res.statusCode = 403;
	res.end('Post will not supported for Leaders '+ req.params.leaderId);
})

.put(cors.corsWithOptions,authenticate.verifyUser,(req,res,next) => {

LeaderId.findById(req.params.leaderId)
	.then((leader)=>{
		if(leader != null && leader.feedbacks.id(req.params.feedbackId) != null){
			if (req.body.rating){
				leader.feedbacks.id(req.params.feedbackId).rating = req.body.rating;
			}
			leader.save()
			.then((leader)=>{
			Leaders.findById(leader._id)
			.populate(feedbacks.author)
			.then((leader)=>{
				res.status = 200;
				res.setHeader('Content-Type','application/json');
				res.json(leader);
			})
			},(err)=>next(err));
		}
		else if (leader == null){
			err = new Error ('Leader '+ req.params.leaderId +' not Found ');
			err.status = 404;
				return next(err);
		}
		else {
				err = new Error ('Feedback with ID : '+ req.params.feedbackId +' not Found ');
				err.status = 404;
				return next(err);
		}
	},(err)=>next(err)).catch((err)=>next(err));
	})

.delete(cors.corsWithOptions,authenticate.verifyUser,(req,res,next)=>{
	
	Leader.findById(req.params.leaderId)
	.then((leader)=>{
		if(leader != null && leader.feedbacks.id(req.params.feedbackId) != null){
			leader.feedbacks.id(req.params.feedbackId).remove();
			leader.save()
			.then((leader)=>{
			Leaders.findById(leader._id)
			.populate(feedbacks.author)
			.then((leader)=>{
				res.status = 200;
				res.setHeader('Content-Type','application/json');
				res.json(leader);
			})
			},(err) => next(err));
		}
		else if (leader == null){
			err = new Error ('Leader '+ req.params.leaderId +' not Found ');
			err.status = 404;
				return next(err);
		}
		else {
				err = new Error ('Feedback with ID : '+ req.params.feedbackId +' not Found ');
				err.status = 404;
				return next(err);
		}
		
	},(err)=>next(err)).catch((err)=>next(err));
	
	});
	
module.exports = leaderRouter;