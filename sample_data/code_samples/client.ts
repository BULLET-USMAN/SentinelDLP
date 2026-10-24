export interface SecurityContext {
  readonly authenticated: boolean;
  readonly tokenScope: string;
}
