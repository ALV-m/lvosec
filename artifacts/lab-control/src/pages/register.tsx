import { useState } from "react";
import type { FormEvent } from "react";
import { Link, Redirect } from "wouter";
import { useRegisterTenant } from "@workspace/api-client-react";
import { Building2, Server } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";

function RegisterPage() {
  const [orgName, setOrgName] = useState("");
  const [contactName, setContactName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [createdSlug, setCreatedSlug] = useState<string | null>(null);

  const registerMutation = useRegisterTenant({
    mutation: {
      onSuccess: (result) => {
        setCreatedSlug(result.tenant.slug);
        toast.success("Your lab is ready — sign in to get started.");
      },
      onError: (error) => toast.error(error.message),
    },
  });

  if (createdSlug) {
    return <Redirect to={`/t/${createdSlug}/login`} replace />;
  }

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!orgName.trim() || !contactName.trim() || !contactEmail.trim()) {
      toast.error("Fill in your organization, contact name and email.");
      return;
    }
    if (!username.trim() || password.length < 6) {
      toast.error("Choose a username and a password of at least 6 characters.");
      return;
    }
    registerMutation.mutate({
      data: {
        orgName: orgName.trim(),
        contactName: contactName.trim(),
        contactEmail: contactEmail.trim(),
        username: username.trim(),
        password,
      },
    });
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-md">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <div className="flex size-12 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <Server className="size-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold">LVO Security</h1>
            <p className="text-sm text-muted-foreground">Create your computer lab workspace</p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Building2 className="size-4" />
              Register your lab
            </CardTitle>
            <CardDescription>
              Set up an isolated dashboard for your organization. Your lab gets
              its own sign-in URL, agents, computers and users.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="orgName">Organization name</Label>
                <Input
                  id="orgName"
                  autoComplete="organization"
                  placeholder="e.g. City Library Computer Lab"
                  value={orgName}
                  onChange={(event) => setOrgName(event.target.value)}
                  autoFocus
                />
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="contactName">Contact name</Label>
                  <Input
                    id="contactName"
                    autoComplete="name"
                    value={contactName}
                    onChange={(event) => setContactName(event.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="contactEmail">Contact email</Label>
                  <Input
                    id="contactEmail"
                    type="email"
                    autoComplete="email"
                    value={contactEmail}
                    onChange={(event) => setContactEmail(event.target.value)}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="username">Admin username</Label>
                <Input
                  id="username"
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Admin password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  At least 6 characters. You can manage more users after signing
                  in.
                </p>
              </div>
              <Button
                type="submit"
                className="w-full"
                disabled={registerMutation.isPending}
              >
                {registerMutation.isPending ? (
                  <Spinner className="size-4" />
                ) : (
                  <Building2 className="size-4" />
                )}
                Create my lab
              </Button>
            </form>
            <p className="mt-4 text-center text-sm text-muted-foreground">
              Already have a lab?{" "}
              <Link href="/" className="font-medium text-foreground underline">
                Go to your sign-in URL
              </Link>
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default RegisterPage;
