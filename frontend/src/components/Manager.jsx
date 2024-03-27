import React,{useState} from 'react'
import axios from 'axios'
import {useNavigate} from 'react-router-dom';


const Manager = () => {
    const navigate = useNavigate();
    
    const [suggestClicked, setSuggestClicked] = useState(false);
    const [breachClicked, setBreachClicked] = useState(false);
    const [storeClicked, setSetstoreClicked] = useState(false);
    const [retrieveClicked, setRetrieveClicked] = useState(false);
    const [passwords, setPasswords] = useState([]);
    const [length, setLength] = useState();
    const [generatedPassword, setGeneratedPassword] = useState("generated password....");
    const [breachCount, setBreachCount] = useState();

    const [password, setPassword] = useState();

    const [url, setUrl] = useState();
    const [username, setUsername] = useState();
    const [newPass, setNewPass] = useState();

    const handleSuggestClick = () =>{
        //console.log("clicked suggest")
        if(suggestClicked){
            setSuggestClicked(false);
        }else{
            setSuggestClicked(true);
        }
    }

    const handleSuggestPassword = async()=>{
        const req = {"length":length};
        const res = await axios.post('http://localhost:5000/generate_password',req);
        //console.log(res.data);
        setGeneratedPassword(res.data.password);
    }
    
    const handleBreachCheck = async()=>{
        const req = {"password":password};
        const res = await axios.post('http://localhost:5000/check_password_breached',req);
        //console.log(res.data);
        setBreachCount(res.data.message);

    }

    const handleStorePassword = async () => {
      const req = {
          "url": url,
          "username": username,
          "password": newPass
      };
      axios.defaults.withCredentials = true;
      const token = localStorage.getItem('jwt'); // Get JWT token from localStorage
      const res = await axios.post('http://localhost:5000/store_password', req, {
          headers: {
              'Authorization': `Bearer ${token}` // Concatenate token into the Authorization header
          }
      });
      if (res.data.message === "Password stored successfully") {
          setUrl('');
          setUsername('');
          setNewPass('');
          setSetstoreClicked(false);
          alert('Password Stored Successfully'); // Add alert here
        }
      };
      
    const handleRetrievePassword = async()=>{
        const token = localStorage.getItem('jwt'); // Get JWT token from localStorage

        const res = await axios.get('http://localhost:5000/retrieve_passwords',{
            headers: {
              'Authorization': `Bearer ${token}` // Concatenate token into the Authorization header
            }
          });
          
          setPasswords(res.data.passwords);

        console.log(passwords);
    }


    const handleBreachClick = () =>{
        console.log("clicked suggest");
        setSuggestClicked(false);

        if(breachClicked){
            setBreachClicked(false);
        }else{
            setBreachClicked(true);
        }
    }

    const handleStoreClick = () =>{
        console.log("clicked suggest")
            setSuggestClicked(false);
        if(storeClicked){
            setSetstoreClicked(false);
        }else{
            setSetstoreClicked(true);
        }
    }
    const handleLogout = async () => {
      //const res = await axios.get('http://localhost:5000/logout'); 
      window.localStorage.setItem("jwt", null);
      navigate('/');
      alert('Logout successful');
  }
  

  return (
    <div>
        <button onClick={handleSuggestClick}>Suggest Password</button>
        {suggestClicked && <div>
            <input type="number" placeholder='Enter Password Length' onChange={(e)=>{setLength(e.target.value)}} />
            <input contentEditable="false" value={generatedPassword}/>
            <button onClick={handleSuggestPassword}>Suggest</button>
            </div>}
        <button onClick={handleBreachClick}>Check Password Breach Status</button>
        {breachClicked && <div>
            <input placeholder='Enter Password' onChange={(e)=>{setPassword(e.target.value)}}/>
            {breachCount && <h5>{breachCount}</h5>}
            <button onClick={handleBreachCheck}>Check</button>
            </div>}
        <button onClick={handleStoreClick}>Store Password</button>
        {storeClicked && <div>
            <input placeholder='Enter App/URL' onChange={(e)=>{setUrl(e.target.value)}}/>
            <input placeholder='usename'onChange={(e)=>{setUsername(e.target.value)}}/>
            <input type='password' placeholder='password' onChange={(e)=>{setNewPass(e.target.value)}}/>
            <button onClick={handleStorePassword}> Store</button>
            </div>}
        <button onClick={handleRetrievePassword}>Retrieve Password</button>
        {passwords && <div className="password-table">
      <h2>Passwords</h2>
      <table>
        <thead>
          <tr>
            <th>App/URL</th>
            <th>Username</th>
            <th>Password</th>
          </tr>
        </thead>
        <tbody>
          {passwords.map((password, index) => (
            <tr key={index}>
              <td>{password.url}</td>
              <td>{password.username}</td>
              <td>{password.password}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>}
        <button onClick={handleLogout}>LOGOUT</button>

    </div>
  )
}

export default Manager