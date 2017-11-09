%Autor: Cleber Peter

%função que cifra e decifra uma entrada através do algoritmo DES
%key -> chave
%debug(0|1) -> possibilita visulizar informações internas da função,
%em tempo de execução
%PTI_char -> texto a ser encriptado ou decriptado
%cipher(1|0) -> (1, encrypta); (0, decrypta)
function CTO_hex = des(key, PTI_char, cipher, debug)
    
    IP = [ 58, 50, 42, 34, 26, 18 ,10, 2, ...
     60, 52, 44, 36, 28, 20, 12, 4, ...
     62, 54, 46, 38, 30, 22, 14, 6, ...
     64, 56, 48, 40, 32, 24, 16, 8, ...
     57, 49, 41, 33, 25, 17, 9, 1, ...
     59, 51, 43, 35, 27, 19, 11, 3, ...
     61, 53, 45, 37, 29, 21, 13, 5, ...
     63, 55, 47, 39, 31, 23, 15, 7 ];% matriz permutação inicial

    invIP = [ 40, 8, 48, 16, 56, 24 ,64, 32, ...
     39, 7, 47, 15, 55, 23, 63, 31, ...
     38, 6 46, 14, 54, 22, 62, 30, ...
     37, 5, 45, 13, 53, 21, 61, 29, ...
     36, 4, 44, 12, 52, 20, 60, 28, ...
     35, 3, 43, 11, 51, 19, 59, 27, ...
     34, 2, 42, 10, 50, 18, 58, 26, ...
     33, 1, 41, 9, 49, 17, 57, 25 ];% matriz inversa da permutação inicial
    
    Expansion = [ 32, 1, 2, 3, 4, 5, ...
     4, 5, 6, 7, 8, 9, ...
     8, 9, 10, 11, 12, 13, ...
     12, 13, 14, 15, 16, 17, ...
     16, 17, 18, 19, 20, 21, ...
     20, 21, 22, 23, 24, 25, ...
     24, 25, 26, 27, 28, 29, ...
     28, 29, 30, 31, 32, 1 ];% matriz expansão
 
    Permutation = [ 16, 7, 20, 21, 29, 12 ,28, 17, ...
     1, 15, 23, 26, 5, 18, 31, 10, ...
     2, 8, 24, 14, 32, 27, 3, 9, ...
     19, 13, 30, 6, 22, 11, 4, 25 ];% matriz permutação
 
    % DES sboxes
    sboxDES1 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7;
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8;
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0;
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ];
 
    sboxDES2 = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10;
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5;
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15;
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ];
 
    sboxDES3 = [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8;
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1;
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7;
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ];
 
    sboxDES4 = [ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15;
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9;
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4;
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 ];
 
    sboxDES5 = [ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9;
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6;
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14;
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ];
 
    sboxDES6 = [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11;
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8;
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6;
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 ];
 
    sboxDES7 = [ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1;
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6;
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2;
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ];
 
    sboxDES8 = [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7;
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2;
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8;
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 ];
 
    sboxes = cell(8, 1); %armazena as boxes em um array
    sboxes{1} = sboxDES1;
    sboxes{2} = sboxDES2;
    sboxes{3} = sboxDES3;
    sboxes{4} = sboxDES4;
    sboxes{5} = sboxDES5;
    sboxes{6} = sboxDES6;
    sboxes{7} = sboxDES7;
    sboxes{8} = sboxDES8;
    
    [roundKey, roundKey_dec] = key_scheduler(convert_to_bin(key),debug); %gera subchaves
    if cipher == 0 %verifica se deve decifrar
        aux = zeros(16,48);
        for i=1:16 
            aux(i,:) = roundKey(17-i,:); %em caso de decifrar inverte a ordem das subchaves
        end
        roundKey = aux;
    end
    
    PTI_char_bin = convert_to_bin(PTI_char); %converte texto claro em binário
    
    PTI_permuted = PTI_char_bin(IP(1:64));%opera PTI_char_bin com IP (permutação inicial)
    
    PTI_permuted_l = PTI_permuted(1:32); % separa em parte alta e baixa
    PTI_permuted_r = PTI_permuted(33:64);
    
    for i=1:16
        
        if debug == 1
            l_str = strcat(strcat(strcat('L',int2str(i)),':'),convert_to_hex(PTI_permuted_l));
            mid_str = ' , ';
            r_str = strcat(strcat(strcat('R',int2str(i)),':'),convert_to_hex(PTI_permuted_r));
            disp(strcat(strcat(l_str,mid_str),r_str));
        end
        
        PTI_permuted_r_expanded = PTI_permuted_r(Expansion(1:48)); % expande parte alta
        PTI_permuted_r_xor = bitxor(PTI_permuted_r_expanded,roundKey(i,:)); % faz xor da parte expandida com a chave da rodada
        
        j = 1;
        PTI_permuted_r_xor_group = zeros(8,6);  % cria matriz para agrupar os bits
        PTI_permuted_r_sboxed = zeros(32); % inicializa matriz resultado dos boxes
        for k=1:8
            PTI_permuted_r_xor_group(k,:) = PTI_permuted_r_xor(j:j+5); % separa em 8 grupos de 6 bits
            lin = bi2de(horzcat(PTI_permuted_r_xor_group(k,1),PTI_permuted_r_xor_group(k,6)),'left-msb')+1; % extrai msb e lsb e converte em decimal para descobrir a linha da box
            col = bi2de((PTI_permuted_r_xor_group(k,2:5)),'left-msb')+1;% extrai bits intermediários e converte em decimal para descobrir a coluna da box
            
            PTI_permuted_r_sboxed(((4*k)-3):(4*k)) = de2bi(sboxes{k}(lin,col),4,'left-msb'); % pega o valor da respectiva box da rodada e converte pra binário e salva na matriz resposta
            j=j+6;
        end
        
        PTI_permuted_r_permuted = PTI_permuted_r_sboxed(Permutation(1:32)); % copia matriz resposta da box com as respectivas substituições já realizadas
        
        dummy = PTI_permuted_r; % salva a parte alta anterior
        PTI_permuted_r = bitxor(PTI_permuted_r_permuted,PTI_permuted_l);  % faz uma xor da matriz resultado com a parte baixa anterior
        PTI_permuted_l = dummy; % copia a parte alta anterior para a próxima parte baixa (inversão de blocos)
        
    end
    
    PTI_permuted_final = zeros(64); % inicializa vetor resposta
    
    PTI_permuted_final(1:32) = PTI_permuted_r; % inverte parte baixa e parte alta 
    PTI_permuted_final(33:64) = PTI_permuted_l;
    
    ecrypted = PTI_permuted_final(invIP(1:64)); % opera com a matriz invIP (permutação inicial inversa)
    
    CTO_hex = convert_to_hex(ecrypted); % converte resposta para hexadecimal
     
end