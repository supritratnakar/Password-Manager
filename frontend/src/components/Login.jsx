import React,{useState} from 'react'
import axios from 'axios'
import {useNavigate} from 'react-router-dom';

const Login = () => {
    const [email, setEmail] = useState();
    const [password, setPassword] = useState();
    const navigate = useNavigate();

    const handleLogin =async(e)=>{
      e.preventDefault();
      const req = {"email":email,"password":password};
      const res = await axios.post('http://localhost:5000/login',req);
      //console.log(res.data.message);
      if(res.status ===200){
        window.localStorage.setItem("jwt",res.data.access_token);
        navigate('/manage');
      }
      e.preventDefault();
    }
  return (
    <div>
        <h1>LOGIN</h1>
        <form onSubmit={handleLogin}>
            <input type="email" placeholder='Email' onChange={(e)=>{setEmail(e.target.value)}}/>
            <input type="password" placeholder='Password' onChange={(e)=>{setPassword(e.target.value)}}/>
            <button type='submit'>Login</button>
        </form>
    </div>
  )
}

export default Login