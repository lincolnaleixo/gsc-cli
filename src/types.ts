export interface SearchConsoleProperty {
  siteUrl: string;
  permissionLevel: string;
}

export interface VerifiedSearchConsoleProperty extends SearchConsoleProperty {
  verified: true;
}

export interface SearchConsoleClicks {
  totalClicks: number;
  startDate: string;
  endDate: string;
  sourceHealthy: true;
}

export interface SearchConsoleApiError {
  code?: number;
  message?: string;
  status?: string;
  errors?: Array<{ reason?: string; message?: string }>;
}
