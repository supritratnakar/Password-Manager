import React,{useState} from 'react'
import axios from 'axios'
import {useNavigate} from 'react-router-dom';
const Signup = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleSignUp = async (e) => {
      e.preventDefault();
      const req = { "email": email, "password": password };
      const res = await axios.post('http://localhost:5000/create_account', req);
      
      if (res.data.message === "Account created successfully") {
          alert('Account created successfully');
          navigate('/login');
        }
    }
  return (
    <div>
        <h1>SIGNUP</h1>
        <form onSubmit={handleSignUp}>
            <input type="email" placeholder='Email' onChange={(e)=>{setEmail(e.target.value)}}/>
            <input type="password" placeholder='Password' onChange={(e)=>{setPassword(e.target.value)}}/>
            <button type='submit'>SignUp</button>
        </form>
    </div>
  )
}

export default Signup