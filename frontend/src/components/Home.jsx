import React from 'react'
import { useNavigate } from 'react-router-dom'
const Home = () => {
    const navigate = useNavigate();
    const handleLogin = ()=>{
        navigate('/login')
    }

    const handleSignUp= ()=>{
        navigate('/signup')
    }

  return (
    <div>
        <button onClick={handleLogin}>Login</button>
        <button onClick={handleSignUp}>Signup</button>
    </div>
  )
}

export default Home