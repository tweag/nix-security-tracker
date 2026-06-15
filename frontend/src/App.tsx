import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Route, Switch } from "wouter-preact";
import { Footer } from "@/components/footer/Footer";
import { HeaderBar } from "@/components/header/HeaderBar";
import { Home } from "@/routes/Home";
import { UserSettings } from "@/routes/UserSettings";
import { Disclaimer } from "./components/header/Disclaimer";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <HeaderBar />
      <Disclaimer />
      <main>
        <Switch>
          <Route path="/ui-v2/" component={Home} />
          <Route path="/ui-v2/user" component={UserSettings} />
          <Route>
            <p>Page not found</p>
          </Route>
        </Switch>
      </main>
      <Footer />
    </QueryClientProvider>
  );
}
