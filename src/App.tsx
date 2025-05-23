import { useState } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  useParams,
  Navigate,
} from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeRaw from "rehype-raw";
import { architectures } from "./data/architectureData";
import "./App.css";

// Sidebar component
const Sidebar = ({ activeArchitecture }: { activeArchitecture: string }) => {
  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <h2>Authentication Architectures</h2>
      </div>
      <nav className="sidebar-nav">
        {architectures.map((arch) => (
          <Link
            key={arch.id}
            to={`/architecture/${arch.id}`}
            className={`sidebar-link ${
              activeArchitecture === arch.id ? "active" : ""
            }`}
          >
            {arch.name}
          </Link>
        ))}
      </nav>
    </div>
  );
};

// Architecture detail page
const ArchitectureDetail = () => {
  const { id } = useParams<{ id: string }>();
  const architecture = architectures.find((arch) => arch.id === id);

  if (!architecture) {
    return <Navigate to="/architecture/overview" />;
  }

  return (
    <div className="architecture-detail">
      <div className="architecture-content">
        <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeRaw]}>
          {architecture.content}
        </ReactMarkdown>
      </div>
    </div>
  );
};

// Home page
const Home = () => {
  return <Navigate to="/architecture/overview" />;
};

// Main App component
function App() {
  const [activeArchitecture] = useState("overview");

  return (
    <Router>
      <div className="app">
        <header className="app-header">
          <h1>Scalable Authentication Architectures for .NET</h1>
        </header>
        <div className="app-container">
          <Sidebar activeArchitecture={activeArchitecture} />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route
                path="/architecture/:id"
                element={<ArchitectureDetail />}
              />
            </Routes>
          </main>
        </div>
        <footer className="app-footer">
          <p>© 2025 Authentication Architecture Research - Felxforce</p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
