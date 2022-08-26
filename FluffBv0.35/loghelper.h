#include<time.h>
#include<stdio.h>

void fuzzlogSR(char* sendbuff,char* revbuff,int pType)
{
    //get date
    time_t timep;
    struct tm *formattime;
    time(&timep);
    formattime=gmtime(&timep);
    char pname[]="./logs/2022_01_01";
    char *logfilename;
    switch (pType)
    {
    case 1:
        char p1[]="./logs/2022_01_01_L2CAP.txt";
        logfilename=p1;
        break;
    case 2:
        char p2[]="./logs/2022_01_01_RFCOMM.txt";
        logfilename=p2;
        break;
    case 3:
        char p3[]="./logs/2022_01_01_OBEX.txt";
        logfilename=p3;
        break;
    default:
        char p0[]="./logs/2022_01_01.txt";
        logfilename=p0;
        break;
    }

    int year=formattime->tm_year+1900;
    for (int i = 10; i >= 7; i--)
    {
        logfilename[i]=year%10+'0';
        year=year/10;
    }

    int month=formattime->tm_mon+1;
    for(int i = 13 ; i >= 12 ; i--)
    {
        logfilename[i]=month%10+'0';
        month=month/10;
    }

    int day=formattime->tm_mday;
    for(int i = 16 ; i >= 15 ; i--)
    {
        logfilename[i]=day%10+'0';
        day=day/10;
    }
    
    FILE *fp=NULL;
    while((fp=fopen(logfilename,"a"))==NULL);
    {
        printf("logfile open failed!\n");
    }
    printf("logfile open successfully\n");
    fprintf(fp,"----------------------------------------------------------------------------\n");
    fprintf(fp,"[+] sendbuff:\n");
    int strLen=strlen(sendbuff);
    int count=0;
    while (count<strLen)
    {
        fprintf(fp,"%02x  ",(unsigned char)sendbuff[count++]);
        if(count%8==0)
            fprintf(fp,"      ");
        if(count%16==0)
            fprintf(fp,"\n");
    }
    
    strLen=strlen(revbuff);
    count=0;
    fprintf(fp,"\n[-]  revbuff:\n");
    while (count<strLen)
    {
        fprintf(fp,"%02x  ",(unsigned char)revbuff[count++]);
        if(count%8==0)
            fprintf(fp,"      ");
        if(count%16==0)
            fprintf(fp,"\n");
    }


    fprintf(fp,"\n----------------------------------------------------------------------------\n");
    
    fclose(fp);
}

void fuzzlog(char* sendbuff,int pType)
{
    //get date
    time_t timep;
    struct tm *formattime;
    time(&timep);
    formattime=gmtime(&timep);
    char pname[]="./logs/2022_01_01";
    char *logfilename;
    switch (pType)
    {
    case 1:
        char p1[]="./logs/2022_01_01_L2CAP.txt";
        logfilename=p1;
        break;
    case 2:
        char p2[]="./logs/2022_01_01_RFCOMM.txt";
        logfilename=p2;
        break;
    case 3:
        char p3[]="./logs/2022_01_01_OBEX.txt";
        logfilename=p3;
        break;
    default:
        char p0[]="./logs/2022_01_01.txt";
        logfilename=p0;
        break;
    }

    int year=formattime->tm_year+1900;
    for (int i = 10; i >= 7; i--)
    {
        logfilename[i]=year%10+'0';
        year=year/10;
    }

    int month=formattime->tm_mon+1;
    for(int i = 13 ; i >= 12 ; i--)
    {
        logfilename[i]=month%10+'0';
        month=month/10;
    }

    int day=formattime->tm_mday;
    for(int i = 16 ; i >= 15 ; i--)
    {
        logfilename[i]=day%10+'0';
        day=day/10;
    }
    
    FILE *fp=NULL;
    while((fp=fopen(logfilename,"a"))==NULL);
    {
        printf("logfile open failed\n");
    }
    printf("logfile open successfully\n");

    fprintf(fp,"----------------------------------------------------------------------------\n");
    fprintf(fp,"[+] sendbuff:\n");
    int strLen=strlen(sendbuff);
    int count=0;
    while (count<strLen)
    {
        fprintf(fp,"%02x  ",(unsigned char)sendbuff[count++]);
        if(count%8==0)
            fprintf(fp,"      ");
        if(count%16==0)
            fprintf(fp,"\n");
    }
    fprintf(fp,"\n----------------------------------------------------------------------------\n");
    fclose(fp);
}