declare global {
  namespace NodeJS {
    interface ProcessEnv {
      HOSTNAME?: string;
      HOST?: string;
      PORT?: string;
      MONGODB_CONNECT_STRING?: string;
      NODE_ENV?: 'development' | 'production';
    }
  }
}

export { };
