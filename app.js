require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3000', // Substitua pela origem permitida
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Métodos HTTP permitidos
}));

const User = require('./models/User');


app.get("/user", async (req,res)=>{
    const query = await User.find();

 return res.status(200).json(query);   

})

app.get("/user/:id",async (req,res)=>{
    const queryId = await User.findById(req.params.id);

 return res.status(200).json(queryId);   

})

app.post("/authentication/users", async (req,res)=>{

 const {name, email, password, confirmPassword, phone, address, city, birthdate} = req.body;
  
  if(!name)
    return res.status(422).json({msg:"Campo 'nome' não preenchido."});

  if(!email)
    return res.status(422).json({msg:"Campo 'email' não prenchido."})
  
  if(!phone)
    return res.status(422).json({msg:"Campo 'telefone' não preenchido."});
  
  if(!address)
    return res.status(422).json({msg:"Campo 'endereço' não preenchido."});
  
  if(!city)
    return res.status(422).json({msg:"Campo 'cidade' não preenchido."});
  
  if(!birthdate)
    return res.status(422).json({msg:"Campo 'data de nascimento' não preenchido."});

  if(password !== confirmPassword)
    return res.status(422).json({msg:"Senha são diferentes."});


const emailExists = await User.findOne({email: email}); 

  if(emailExists)
    return res.status(422).json({msg: "Email já existente, por favor utilize outro email ou realize login."});

const salt = await bcrypt.genSalt(12);
const hash = await bcrypt.hash(password, salt);


const user = new User({
    name, 
    email, 
    password: hash,  
    phone, 
    address, 
    city, 
    birthdate
});

    try{
      await user.save();
    }

    catch(error){
      console.log(error);
      return res.status(500).json({msg:"Aconteceu algum erro por favor tentar mais tarde"});  
    }
})


app.post("/authentication/login", async (req,res) =>{
    
 const {email,password} = req.body;

  if(!email)
    return res.status(422).json({msg:"Email é obrigatório."});

 const verifyUser = await User.findOne({email: email});
 
  if(!verifyUser)
    return res.status(422).json({msg:"Usuário não encontrado"});

    try{
       const secret = process.env.SECRET;
       const token = jwt.sign({id: verifyUser.id}, secret);
       
        
        return res.status(200).json({msg:"Autenticação realizada com sucesso.", token});
        
    }
    
    catch(error){
     console.log(error)
       
        return res.status(500).json({mag:"Ocorreu algum erro, favor tentar mais tarde."});       
    }
})


app.get("/user/:id", checkToken ,async (req,res)=>{
 
 const id = req.params.id;
 const user = await User.findById(id, '-password');
 

 if(!user)
    return res.status(404).json({msg:"Usuário não encontrado"});

 return res.status(200).json({user});
})

function checkToken(req, res, next){
    
   const autHeader = req.headers['authorization'];
   const token = autHeader && autHeader.split(" ")[1];
   
    if(!token)
        return res.status(401).json({msg:"Acesso negado."});

    
    try{
        const secret = process.env.SECRET;

        jwt.verify(token, secret);

        next();

    }
    
    catch(error){
        console.log(error)
        return res.status(400).json({msg:"Token inválido"});
    }
}

app.put("/authentication/update/:id", async (req,res)=>{
    
    try{
  const update = await User.findByIdAndUpdate(req.params.id,{
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    phone: req.body.phone,
    address: req.body.address,
    city: req.body.city,
    birthdate: req.body.birthdate
    },
     {new: true});
     
      return res.status(200).json(update);
      }
      catch(error){
        console.log(error);
        return res.status(500).json({msg:"Erro ao processar mudanças, favor tentar mais tarde."});
      } 
})

app.delete("/authentication/delete/:id", async (req,res)=>{
    
  const remove = await User.findByIdAndDelete(req.params.id);

  if(!remove)
    return res.status(404).json({msg:"Ocorreu um erro na remoção do usuário"});

  return res.status(200).json({msg:"Usuário excluido com sucesso!"})
})


const corsOptions = {
  origin: 'http://localhost:3000', // Substitua por sua origem permitida
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Métodos HTTP permitidos
};

app.use(cors(corsOptions));


const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.sndvith.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
.then(()=>{
    app.listen(4000);  
    console.log("Conexão ao banco de dados bem sucedida!");
}).catch((err)=> console.log(err))
