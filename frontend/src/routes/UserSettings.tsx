import { AutoSubscribeToggle } from "../components/AutoSubscribeToggle";
import { useAuth } from "../hooks/useAuth";

export function UserSettings() {
  const { isAuthenticated } = useAuth();

  if (isAuthenticated) {
    return (
      <div className="column">
        <h1 className="page-title">User settings</h1>
        <AutoSubscribeToggle />
      </div>
    );
  }
}
