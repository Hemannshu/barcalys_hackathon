// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
import { getAuth } from "firebase/auth"; // ✅ Add this line
import { getFirestore } from "firebase/firestore";


// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBN5yQuMSiH8WLfc42hY7zHuaMzXGrpVn0",
  authDomain: "barclayshackathon-cbc33.firebaseapp.com",
  projectId: "barclayshackathon-cbc33",
  storageBucket: "barclayshackathon-cbc33.appspot.com", // 🔄 fixed `.app` to `.appspot.com`
  messagingSenderId: "507099418548",
  appId: "1:507099418548:web:032988020859d9498c6ce1",
  measurementId: "G-MLJD9V1QVV"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
const auth = getAuth(app); // ✅ Initialize auth
const db = getFirestore(app); // Initialize Firestore

export { auth, app ,db};
