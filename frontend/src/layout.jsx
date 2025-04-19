// Layout.jsx (or your main layout component)
import { Outlet } from 'react-router-dom';
import Sidebar from './sidebar';

const Layout = () => {
  return (
    <div className="app-container">
      <Sidebar />
      <main className="main-content">
        <Outlet /> {/* This is where your page content will render */}
      </main>
    </div>
  );
};

export default Layout;